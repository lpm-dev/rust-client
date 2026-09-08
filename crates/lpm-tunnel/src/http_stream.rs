use crate::protocol::ClientMessage;
use base64::{Engine, engine::general_purpose::STANDARD};
use lpm_common::LpmError;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const CHUNK_BYTES: usize = 64 * 1024;
const CAPTURE_BYTES: usize = 64 * 1024;

pub(crate) struct StreamOutput {
    pub(crate) messages: mpsc::Sender<ClientMessage>,
    pub(crate) credits: mpsc::Receiver<()>,
    pub(crate) cancel: CancellationToken,
}

pub(crate) struct StreamCapture {
    pub(crate) body: Vec<u8>,
    pub(crate) incomplete: bool,
    pub(crate) failed: bool,
}

impl StreamOutput {
    pub(crate) async fn forward(
        mut self,
        id: &str,
        status: u16,
        headers: &HashMap<String, String>,
        mut response: reqwest::Response,
    ) -> Result<StreamCapture, LpmError> {
        self.messages
            .send(ClientMessage::HttpResponseStart {
                id: id.to_string(),
                status,
                headers: headers.clone(),
            })
            .await
            .map_err(|_| LpmError::Tunnel("response channel closed".into()))?;
        let mut capture = StreamCapture {
            body: Vec::new(),
            incomplete: false,
            failed: false,
        };
        let mut buffered = None;
        loop {
            let next = async {
                self.credits.recv().await?;
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
                Some(Ok(chunk))
            };
            let chunk = tokio::select! {
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
                    let remaining = CAPTURE_BYTES.saturating_sub(capture.body.len());
                    capture
                        .body
                        .extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                    capture.incomplete |= chunk.len() > remaining;
                    let message = ClientMessage::HttpResponseChunk {
                        id: id.to_string(),
                        body: STANDARD.encode(chunk),
                    };
                    tokio::select! {
                        _ = self.cancel.cancelled() => { capture.failed = true; break; }
                        result = self.messages.send(message) => if result.is_err() { capture.failed = true; break; },
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
                .forward("stream", 200, &HashMap::new(), response)
                .await
        });
        assert!(matches!(
            received.recv().await,
            Some(ClientMessage::HttpResponseStart { .. })
        ));
        credits.send(()).await.unwrap();
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(1), received.recv())
            .await
            .expect("one relay credit must reach the next nonempty upstream chunk");
        match chunk {
            Some(ClientMessage::HttpResponseChunk { body, .. }) => {
                assert_eq!(STANDARD.decode(body).unwrap(), b"data: ready\n\n");
            }
            other => panic!("expected stream chunk, received {other:?}"),
        }
        credits.send(()).await.unwrap();
        let capture = task.await.unwrap().unwrap();
        assert_eq!(capture.body, b"data: ready\n\n");
        assert!(!capture.failed);
        assert!(!capture.incomplete);
    }
}
