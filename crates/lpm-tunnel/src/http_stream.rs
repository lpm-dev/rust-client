use crate::protocol::ClientMessage;
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::FutureExt;
use lpm_common::LpmError;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const CHUNK_BYTES: usize = 64 * 1024;
const CAPTURE_BYTES: usize = 64 * 1024;

pub(crate) struct StreamOutput {
    pub(crate) messages: mpsc::Sender<crate::client::HttpRelayFrame>,
    pub(crate) credits: mpsc::Receiver<u64>,
    pub(crate) cancel: CancellationToken,
}

pub(crate) struct StreamCapture {
    pub(crate) body: Vec<u8>,
    pub(crate) incomplete: bool,
    pub(crate) failed: bool,
    pub(crate) next_sequence: u64,
}

impl StreamOutput {
    pub(crate) async fn forward(
        mut self,
        id: &str,
        status: u16,
        headers: &HashMap<String, String>,
        bodyless: bool,
        mut response: reqwest::Response,
        deadline: tokio::time::Instant,
    ) -> Result<StreamCapture, LpmError> {
        self.messages
            .send(crate::client::HttpRelayFrame::Stream(
                ClientMessage::HttpResponseStart {
                    id: id.to_string(),
                    status,
                    headers: headers.clone(),
                },
            ))
            .await
            .map_err(|_| LpmError::Tunnel("response channel closed".into()))?;
        let mut capture = StreamCapture {
            body: Vec::new(),
            incomplete: false,
            failed: false,
            next_sequence: 1,
        };
        if bodyless {
            return Ok(capture);
        }
        let is_sse = headers.get("content-type").is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
        });
        let mut buffered = None;
        let mut received_bytes = 0usize;
        let mut upstream_failed = false;
        let mut upstream_finished = false;
        loop {
            let next = async {
                let credit = self.credits.recv().await?;
                if credit != capture.next_sequence {
                    return Some(Err(()));
                }
                if upstream_finished && buffered.is_none() {
                    return None;
                }
                while buffered.is_none() {
                    match response.chunk().await {
                        Ok(Some(bytes)) if bytes.is_empty() => continue,
                        Ok(Some(bytes)) => buffered = Some(bytes),
                        Ok(None) => return None,
                        Err(_) => return Some(Err(())),
                    }
                }
                let bytes = buffered.as_mut()?;
                let chunk = bytes.split_to(bytes.len().min(CHUNK_BYTES));
                if bytes.is_empty() {
                    buffered = None;
                }
                if !is_sse && chunk.len() < CHUNK_BYTES {
                    let mut joined = Vec::with_capacity(CHUNK_BYTES);
                    joined.extend_from_slice(&chunk);
                    for _ in 0..1024 {
                        if joined.len() == CHUNK_BYTES {
                            break;
                        }
                        tokio::task::yield_now().await;
                        let Some(next) = response.chunk().now_or_never() else {
                            break;
                        };
                        match next {
                            Ok(Some(mut next)) => {
                                let take = next.len().min(CHUNK_BYTES - joined.len());
                                joined.extend_from_slice(&next.split_to(take));
                                if !next.is_empty() {
                                    buffered = Some(next);
                                    break;
                                }
                            }
                            Ok(None) => {
                                upstream_finished = true;
                                break;
                            }
                            Err(_) => {
                                upstream_failed = true;
                                break;
                            }
                        }
                    }
                    Some(Ok(joined.into()))
                } else {
                    Some(Ok(chunk))
                }
            };
            let chunk = tokio::select! {
                _ = tokio::time::sleep_until(deadline) => { capture.failed = true; break; }
                _ = self.cancel.cancelled() => { capture.failed = true; break; }
                chunk = next => chunk,
            };
            match chunk {
                None => break,
                Some(Err(())) => {
                    capture.failed = true;
                    break;
                }
                Some(Ok(chunk)) => {
                    received_bytes += chunk.len();
                    if received_bytes > 50 * 1024 * 1024 {
                        capture.failed = true;
                        break;
                    }
                    let remaining = CAPTURE_BYTES.saturating_sub(capture.body.len());
                    capture
                        .body
                        .extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    capture.incomplete |= chunk.len() > remaining;
                    let message = ClientMessage::HttpResponseChunk {
                        id: id.to_string(),
                        body: STANDARD.encode(chunk),
                        seq: capture.next_sequence,
                    };
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => { capture.failed = true; break; }
                        _ = self.cancel.cancelled() => { capture.failed = true; break; }
                        result = self.messages.send(crate::client::HttpRelayFrame::Stream(message)) => if result.is_err() { capture.failed = true; break; },
                    }
                    capture.next_sequence += 1;
                    if upstream_failed {
                        capture.failed = true;
                        break;
                    }
                }
            }
        }
        capture.incomplete |= capture.failed;
        Ok(capture)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    #[tokio::test]
    async fn ordinary_upstream_failure_preserves_the_available_prefix() {
        let body = reqwest::Body::wrap_stream(futures_util::stream::iter([
            Ok(b"prefix".to_vec()),
            Err(std::io::Error::other("origin failed")),
        ]));
        let response = tokio_tungstenite::tungstenite::http::Response::new(body).into();
        let (messages, mut received) = mpsc::channel(2);
        let (credits, demand) = mpsc::channel(1);
        let output = StreamOutput {
            messages,
            credits: demand,
            cancel: CancellationToken::new(),
        };
        let task = tokio::spawn(async move {
            output
                .forward(
                    "body",
                    200,
                    &HashMap::new(),
                    false,
                    response,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                )
                .await
        });
        received.recv().await.unwrap();
        credits.send(1).await.unwrap();
        let Some(crate::client::HttpRelayFrame::Stream(ClientMessage::HttpResponseChunk {
            body,
            seq,
            ..
        })) = received.recv().await
        else {
            panic!("origin prefix must be delivered")
        };
        assert_eq!(seq, 1);
        assert_eq!(STANDARD.decode(body).unwrap(), b"prefix");
        let capture = task.await.unwrap().unwrap();
        assert_eq!(capture.body, b"prefix");
        assert!(capture.failed);
        assert!(capture.incomplete);
        assert_eq!(capture.next_sequence, 2);
    }

    #[tokio::test]
    async fn ordinary_background_body_frames_share_bounded_relay_chunks() {
        let (sender, receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            for _ in 0..128 {
                sender
                    .send(Ok::<_, std::io::Error>(vec![42; 1024]))
                    .await
                    .unwrap();
            }
        });
        let body = reqwest::Body::wrap_stream(
            futures_util::stream::unfold(receiver, |mut receiver| async move {
                receiver.recv().await.map(|chunk| (chunk, receiver))
            })
            .fuse(),
        );
        let response = tokio_tungstenite::tungstenite::http::Response::new(body).into();
        let (messages, mut received) = mpsc::channel(1);
        let (credits, demand) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            StreamOutput {
                messages,
                credits: demand,
                cancel: CancellationToken::new(),
            }
            .forward(
                "body",
                200,
                &HashMap::new(),
                false,
                response,
                tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            )
            .await
        });
        received.recv().await.unwrap();
        let mut chunks = 0;
        let mut delivered = Vec::with_capacity(128 * 1024);
        for sequence in 1..=129 {
            credits.send(sequence).await.unwrap();
            let Some(frame) = received.recv().await else {
                break;
            };
            let crate::client::HttpRelayFrame::Stream(ClientMessage::HttpResponseChunk {
                body,
                seq,
                ..
            }) = frame
            else {
                panic!("unexpected frame")
            };
            assert_eq!(seq, sequence);
            let decoded = STANDARD.decode(body).unwrap();
            assert!(decoded.len() <= CHUNK_BYTES);
            delivered.extend_from_slice(&decoded);
            chunks += 1;
        }
        let capture = task.await.unwrap().unwrap();
        assert!(!capture.failed);
        assert_eq!(delivered, vec![42; 128 * 1024]);
        assert_eq!(
            chunks, 2,
            "background origin scheduling must not amplify relay messages"
        );
    }

    #[tokio::test]
    async fn ordinary_ready_body_frames_share_one_bounded_relay_chunk() {
        let body = reqwest::Body::wrap_stream(futures_util::stream::iter(
            (0..128).map(|_| Ok::<_, std::io::Error>(vec![42; 1024])),
        ));
        let response = tokio_tungstenite::tungstenite::http::Response::new(body).into();
        let (messages, mut received) = mpsc::channel(1);
        let (credits, demand) = mpsc::channel(1);
        let output = StreamOutput {
            messages,
            credits: demand,
            cancel: CancellationToken::new(),
        };
        let task = tokio::spawn(async move {
            output
                .forward(
                    "body",
                    200,
                    &HashMap::new(),
                    false,
                    response,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                )
                .await
        });
        assert!(matches!(
            received.recv().await,
            Some(crate::client::HttpRelayFrame::Stream(
                ClientMessage::HttpResponseStart { .. }
            ))
        ));
        let mut chunks = 0;
        let mut total = 0;
        loop {
            if credits.send(chunks + 1).await.is_err() {
                break;
            }
            let Some(message) = received.recv().await else {
                break;
            };
            let crate::client::HttpRelayFrame::Stream(ClientMessage::HttpResponseChunk {
                body,
                seq,
                ..
            }) = message
            else {
                panic!("expected chunk")
            };
            chunks += 1;
            assert_eq!(seq, chunks);
            let bytes = STANDARD.decode(body).unwrap();
            assert!(bytes.len() <= CHUNK_BYTES);
            assert!(bytes.iter().all(|value| *value == 42));
            total += bytes.len();
        }
        let capture = task.await.unwrap().unwrap();
        assert_eq!(total, 128 * 1024);
        assert_eq!(
            chunks, 2,
            "small origin frames must not amplify paid relay message count"
        );
        assert!(!capture.failed);
        assert!(capture.incomplete);
    }

    #[tokio::test]
    async fn empty_upstream_chunks_do_not_consume_relay_demand() {
        let body = reqwest::Body::wrap_stream(futures_util::stream::iter([
            Ok::<_, std::io::Error>(Vec::new()),
            Ok(b"data: ready\n\n".to_vec()),
        ]));
        let response = tokio_tungstenite::tungstenite::http::Response::new(body).into();
        let (messages, mut received) = mpsc::channel(4);
        let (credits, demand) = mpsc::channel(1);
        let output = StreamOutput {
            messages,
            credits: demand,
            cancel: CancellationToken::new(),
        };
        let task = tokio::spawn(async move {
            output
                .forward(
                    "stream",
                    200,
                    &HashMap::new(),
                    false,
                    response,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(30),
                )
                .await
        });
        assert!(matches!(
            received.recv().await,
            Some(crate::client::HttpRelayFrame::Stream(
                ClientMessage::HttpResponseStart { .. }
            ))
        ));
        credits.send(1).await.unwrap();
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(1), received.recv())
            .await
            .expect("one relay credit must reach the next nonempty upstream chunk");
        match chunk {
            Some(crate::client::HttpRelayFrame::Stream(ClientMessage::HttpResponseChunk {
                body,
                ..
            })) => {
                assert_eq!(STANDARD.decode(body).unwrap(), b"data: ready\n\n");
            }
            _ => panic!("expected stream chunk"),
        }
        credits.send(2).await.unwrap();
        let capture = task.await.unwrap().unwrap();
        assert_eq!(capture.body, b"data: ready\n\n");
        assert!(!capture.failed);
        assert!(!capture.incomplete);
    }
}
