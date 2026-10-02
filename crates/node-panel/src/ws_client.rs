use crate::{Auth, WsEvent, WsHint, parse_ws_hint, parse_ws_message, ws_hint::EventName};
use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use serde_json::Value;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

const MAX_WS_MESSAGE: usize = 10 * 1024 * 1024;

enum Dispatch<'a> {
    Events(&'a mpsc::Sender<WsEvent>),
    Hints(&'a mpsc::Sender<WsHint>),
}

fn check_auth_ack(first: Message) -> Result<(), WsClientError> {
    let Message::Text(text) = first else {
        return Err(WsClientError::AuthRejected);
    };
    let value: Value = serde_json::from_str(&text).map_err(|_| WsClientError::AuthRejected)?;
    if value.get("event").and_then(Value::as_str) == Some("auth.success") {
        Ok(())
    } else {
        Err(WsClientError::AuthRejected)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WsClientError {
    #[error("websocket URL must use wss")]
    InsecureUrl,
    #[error("invalid websocket URL")]
    Url,
    #[error("websocket connection failed")]
    Connect,
    #[error("websocket message failed")]
    Message,
    #[error("websocket event queue is full")]
    QueueFull,
    #[error("websocket event decode failed")]
    Decode,
    #[error("panel websocket authentication rejected")]
    AuthRejected,
}

#[derive(Clone, Debug)]
pub struct WsBackoff {
    current: Duration,
    initial: Duration,
    max: Duration,
}
impl WsBackoff {
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            current: initial,
            initial,
            max,
        }
    }
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = self.current.saturating_mul(2).min(self.max);
        delay
    }
    pub fn reset(&mut self) {
        self.current = self.initial;
    }
}

pub struct WsClient {
    base: Url,
    auth: Auth,
    backoff_initial: Duration,
    backoff_max: Duration,
}
impl WsClient {
    /// Handshake-discovered endpoints must remain on the configured HTTPS origin.
    pub fn for_panel(
        panel: &str,
        endpoint: &str,
        auth: Auth,
        initial: Duration,
        max: Duration,
    ) -> Result<Self, WsClientError> {
        let panel = Url::parse(panel).map_err(|_| WsClientError::Url)?;
        let ws = Url::parse(endpoint).map_err(|_| WsClientError::Url)?;
        if panel.scheme() != "https"
            || ws.scheme() != "wss"
            || panel.host_str() != ws.host_str()
            || panel.port_or_known_default() != ws.port_or_known_default()
        {
            return Err(WsClientError::InsecureUrl);
        }
        Self::new(endpoint, auth, initial, max)
    }
    pub fn new(
        base: &str,
        auth: Auth,
        backoff_initial: Duration,
        backoff_max: Duration,
    ) -> Result<Self, WsClientError> {
        auth.validate().map_err(|_| WsClientError::Url)?;
        let url = Url::parse(base).map_err(|_| WsClientError::Url)?;
        if url.scheme() != "wss"
            || url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(WsClientError::InsecureUrl);
        }
        Ok(Self {
            base: url,
            auth,
            backoff_initial: backoff_initial.max(Duration::from_millis(1)),
            backoff_max: backoff_max.max(backoff_initial),
        })
    }
    pub fn authenticated_url_for_test(&self) -> Result<Url, WsClientError> {
        self.authenticated_url()
    }
    fn authenticated_url(&self) -> Result<Url, WsClientError> {
        let mut url = self.base.clone();
        let mut query = url.query_pairs_mut();
        query
            .append_pair("token", &self.auth.token)
            .append_pair("node_id", &self.auth.node_id.to_string());
        if let Some(machine_id) = self.auth.machine_id {
            query.append_pair("machine_id", &machine_id.to_string());
        } else if let Some(node_type) = &self.auth.node_type {
            query.append_pair("node_type", node_type);
        }
        drop(query);
        Ok(url)
    }
    /// Runs until cancellation. The queue is bounded by the caller; a full queue fails closed.
    pub async fn run(
        &self,
        stop: tokio::sync::watch::Receiver<bool>,
        tx: mpsc::Sender<WsEvent>,
    ) -> Result<(), WsClientError> {
        self.run_dispatch(stop, Dispatch::Events(&tx)).await
    }
    /// A full hint queue already contains the resync notification for this node.
    pub async fn run_hints(
        &self,
        stop: tokio::sync::watch::Receiver<bool>,
        tx: mpsc::Sender<WsHint>,
    ) -> Result<(), WsClientError> {
        self.run_dispatch(stop, Dispatch::Hints(&tx)).await
    }
    async fn run_dispatch(
        &self,
        mut stop: tokio::sync::watch::Receiver<bool>,
        dispatch: Dispatch<'_>,
    ) -> Result<(), WsClientError> {
        let mut backoff = WsBackoff::new(self.backoff_initial, self.backoff_max);
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            match self.run_connection(&mut stop, &dispatch).await {
                Ok(()) => {
                    if *stop.borrow() {
                        return Ok(());
                    }
                }
                Err(err @ (WsClientError::QueueFull | WsClientError::AuthRejected)) => {
                    return Err(err);
                }
                Err(_) => {}
            }
            let delay = backoff.next_delay();
            tokio::select! { _ = tokio::time::sleep(delay) => {}, changed = stop.changed() => { if changed.is_err() || *stop.borrow() { return Ok(()); } } }
        }
    }
    async fn run_connection(
        &self,
        stop: &mut tokio::sync::watch::Receiver<bool>,
        dispatch: &Dispatch<'_>,
    ) -> Result<(), WsClientError> {
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(MAX_WS_MESSAGE);
        config.max_frame_size = Some(MAX_WS_MESSAGE);
        config.max_write_buffer_size = MAX_WS_MESSAGE + 1024;
        let connect = connect_async_with_config(
            self.authenticated_url()
                .map_err(|_| WsClientError::Url)?
                .to_string(),
            Some(config),
            false,
        );
        let (mut socket, _) = tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { return Ok(()); }
                return Err(WsClientError::Connect);
            }
            result = tokio::time::timeout(Duration::from_secs(15), connect) => {
                result.map_err(|_| WsClientError::Connect)?.map_err(|_| WsClientError::Connect)?
            }
        };
        // The panel authenticates via the handshake query and acknowledges it in
        // the first message. Never dispatch sync events before that acknowledgement.
        let first = tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { return Ok(()); }
                return Err(WsClientError::Connect);
            }
            result = tokio::time::timeout(Duration::from_secs(15), socket.next()) => {
                result.map_err(|_| WsClientError::Connect)?
                    .ok_or(WsClientError::Connect)?
                    .map_err(|_| WsClientError::Connect)?
            }
        };
        check_auth_ack(first)?;
        loop {
            let message = tokio::select! { changed = stop.changed() => { if changed.is_err() || *stop.borrow() { let _ = socket.close(None).await; return Ok(()); } continue; }, next = socket.next() => next };
            let Some(message) = message else {
                return Err(WsClientError::Message);
            };
            let message = message.map_err(|_| WsClientError::Message)?;
            match message {
                Message::Ping(payload) => {
                    socket
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|_| WsClientError::Message)?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => return Err(WsClientError::Message),
                Message::Text(text) => self.handle_text(text.as_bytes(), dispatch)?,
                Message::Binary(bytes) => self.handle_text(&bytes, dispatch)?,
                _ => {}
            }
        }
    }
    fn handle_text(&self, bytes: &[u8], dispatch: &Dispatch<'_>) -> Result<(), WsClientError> {
        if bytes.len() > MAX_WS_MESSAGE {
            return Err(WsClientError::Decode);
        }
        match dispatch {
            Dispatch::Events(tx) => {
                let name: EventName =
                    serde_json::from_slice(bytes).map_err(|_| WsClientError::Decode)?;
                if name.event == "auth.success" {
                    return Ok(());
                }
                if let Some(event) = parse_ws_message(bytes).map_err(|_| WsClientError::Decode)? {
                    tx.try_send(event).map_err(|_| WsClientError::QueueFull)?;
                }
            }
            Dispatch::Hints(tx) => {
                if let Some(hint) = parse_ws_hint(bytes).map_err(|_| WsClientError::Decode)?
                    && hint.node_id == Some(self.auth.node_id)
                {
                    match tx.try_send(hint) {
                        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            return Err(WsClientError::QueueFull);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn hint_bursts_coalesce_without_retaining_user_payloads_or_other_nodes() {
        let client = WsClient::new(
            "wss://panel.example.com/ws",
            Auth::machine("fixture", 1, 7),
            Duration::from_secs(1),
            Duration::from_secs(10),
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        client
            .handle_text(
                br#"{"event":"sync.users","data":{"node_id":8,"users":[]}}"#,
                &Dispatch::Hints(&tx),
            )
            .unwrap();
        assert!(rx.try_recv().is_err());
        for _ in 0..100 {
            client
                .handle_text(
                    br#"{"event":"sync.users","data":{"node_id":7,"users":[{"uuid":"ignored"}]}}"#,
                    &Dispatch::Hints(&tx),
                )
                .unwrap();
        }
        assert_eq!(rx.try_recv().unwrap(), WsHint { node_id: Some(7) });
        assert!(rx.try_recv().is_err());
    }
    #[test]
    fn authentication_ack_is_exact_and_does_not_reflect_server_error() {
        for message in [
            r#"{"event":"error","data":{"message":"secret"}}"#,
            r#"{"event":"sync.users","data":{"users":[]}}"#,
            r#"{"event":"auth.successful"}"#,
            r#"{"event":"error","data":"auth.success"}"#,
            "not-json",
        ] {
            assert_eq!(
                check_auth_ack(Message::Text(message.into())),
                Err(WsClientError::AuthRejected)
            );
        }
        assert_eq!(
            check_auth_ack(Message::Text(r#"{"event":"auth.success"}"#.into())),
            Ok(())
        );
    }
}
