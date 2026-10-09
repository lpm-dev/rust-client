use futures_util::{Sink, Stream, StreamExt};
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Error, Message},
};

pub(super) struct MockRelay<S> {
    socket: WebSocketStream<S>,
    sequence: u64,
    pulls: HashMap<String, u64>,
    ready: bool,
}

pub(super) async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
) -> Result<MockRelay<S>, Error> {
    Ok(MockRelay {
        socket: tokio_tungstenite::accept_async(stream).await?,
        sequence: 0,
        pulls: HashMap::new(),
        ready: false,
    })
}

pub(super) async fn accept_with_headers<S, C>(stream: S, callback: C) -> Result<MockRelay<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: tokio_tungstenite::tungstenite::handshake::server::Callback + Unpin,
{
    Ok(MockRelay {
        socket: tokio_tungstenite::accept_hdr_async(stream, callback).await?,
        sequence: 0,
        pulls: HashMap::new(),
        ready: false,
    })
}

impl<S: AsyncRead + AsyncWrite + Unpin> MockRelay<S> {
    pub(super) async fn close(
        &mut self,
        frame: Option<tokio_tungstenite::tungstenite::protocol::CloseFrame<'static>>,
    ) -> Result<(), Error> {
        while !self.ready {
            let Some(message) = self.socket.next().await else {
                break;
            };
            if let Message::Text(text) = message? {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                self.ready = value["type"] == "client_ready";
            }
        }
        self.socket.close(frame).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Sink<Message> for MockRelay<S> {
    type Error = Error;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.socket).poll_ready(cx)
    }
    fn start_send(mut self: Pin<&mut Self>, message: Message) -> Result<(), Error> {
        let message = if let Message::Text(text) = message {
            let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
            if value["type"] == "hello" {
                value["protocol"] = serde_json::json!(4);
            }
            if value["type"] == "http_response_pull" {
                let id = value["id"].as_str().unwrap().to_owned();
                let next = self.pulls.entry(id).or_insert(0);
                *next += 1;
                value["seq"] = serde_json::json!(*next);
            }
            self.sequence += 1;
            value["transport_seq"] = serde_json::json!(self.sequence);
            value["transport_ack_nonce"] =
                serde_json::json!(format!("00000000-0000-4000-8000-{:012x}", self.sequence));
            Message::Text(value.to_string())
        } else {
            message
        };
        Pin::new(&mut self.socket).start_send(message)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.socket).poll_close(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Stream for MockRelay<S> {
    type Item = Result<Message, Error>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let next = Pin::new(&mut self.socket).poll_next(cx);
            if let Poll::Ready(Some(Ok(Message::Text(ref text)))) = next
                && let Ok(value) = serde_json::from_str::<serde_json::Value>(text)
                && matches!(
                    value["type"].as_str(),
                    Some("transport_ack" | "client_ready")
                )
            {
                self.ready |= value["type"] == "client_ready";
                continue;
            }
            return next;
        }
    }
}
