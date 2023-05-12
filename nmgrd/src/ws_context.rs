use anyhow::{Context as _, Result};
use backon::{ExponentialBuilder, Retryable};
use core::time::Duration;
use libp2p::futures::{SinkExt, StreamExt};
use std::collections::VecDeque;
use std::io::ErrorKind;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{
    error::Error as TsError, error::ProtocolError, Message as WsMessage,
};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A connection closure tolerant web socket context
pub struct WsContext {
    url: String,
    ws_conn: Option<WsStream>,
    send_queue: VecDeque<WsMessage>,
}

impl WsContext {
    pub async fn new(url: &str) -> Result<Self> {
        let this = Self {
            url: url.to_string(),
            ws_conn: None,
            send_queue: VecDeque::new(),
        };
        Ok(this)
    }
    async fn connect(&mut self) -> Result<&mut WsStream> {
        let (mut ws_conn, _resp) = (|| async {
            log::info!("Attempting ws connection to {}", self.url);
            let res: Result<_> = Ok(connect_async(&self.url).await?);
            log::info!("Ws connection to {} established", self.url);
            res
        })
        .retry(
            &ExponentialBuilder::default()
                .with_max_times(usize::MAX)
                .with_min_delay(Duration::from_millis(500))
                .with_max_delay(Duration::from_millis(15_000)),
        )
        .when(|e| {
            let Some(e) = e.downcast_ref::<TsError>() else {
                return false;
            };
            let TsError::Io(e) = e else {
                return false;
            };
            e.kind() == ErrorKind::ConnectionRefused
        })
        .await?;
        while let Some(msg) = self.send_queue.pop_front() {
            ws_conn.send(msg).await?;
        }
        Ok(self.ws_conn.insert(ws_conn))
    }
    pub async fn select_next_some(&mut self) -> Result<WsMessage> {
        loop {
            // TODO: figure out how to move this logic into the connect function,
            // all attempts yielded lifetime errors.
            let conn = if let Some(conn) = &mut self.ws_conn {
                conn
            } else {
                self.connect().await?
            };
            let msg = match conn.select_next_some().await {
                Ok(v) => v,
                Err(TsError::Io(e)) if e.kind() == ErrorKind::ConnectionReset => {
                    self.ws_conn = None;
                    continue;
                }
                Err(TsError::Protocol(ProtocolError::ResetWithoutClosingHandshake)) => {
                    self.ws_conn = None;
                    continue;
                }
                e => e.with_context(|| format!("Error connecting to websocket '{}'", self.url))?,
            };
            if msg.is_close() {
                self.ws_conn = None;
            }
            return Ok(msg);
        }
    }
    pub async fn send(&mut self, msg: WsMessage) -> Result<()> {
        if let Some(conn) = &mut self.ws_conn {
            conn.send(msg).await?;
        } else {
            self.send_queue.push_back(msg);
        }

        Ok(())
    }
}
