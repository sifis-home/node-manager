use anyhow::{Context as _, Result};
use backon::{BackoffBuilder, ExponentialBackoff, ExponentialBuilder};
use core::time::Duration;
use libp2p::futures::{SinkExt, StreamExt};
use std::collections::VecDeque;
use std::io::ErrorKind;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::{
    error::Error as TsError, error::ProtocolError, Message as WsMessage,
};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

enum ConnOrWaiting {
    Conn(WsStream),
    Waiting(ExponentialBackoff, Option<Instant>),
}

impl ConnOrWaiting {
    fn insert(&mut self, conn: WsStream) -> &mut WsStream {
        *self = ConnOrWaiting::Conn(conn);
        match self {
            ConnOrWaiting::Conn(conn) => conn,
            ConnOrWaiting::Waiting(..) => unreachable!(),
        }
    }
    fn reset(&mut self) {
        *self = ConnOrWaiting::Waiting(make_backoff(), None);
    }
}

/// A connection closure tolerant web socket context
pub struct WsContext {
    url: String,
    ws_conn: ConnOrWaiting,
    send_queue: VecDeque<WsMessage>,
}

impl WsContext {
    pub async fn new(url: &str) -> Result<Self> {
        let this = Self {
            url: url.to_string(),
            ws_conn: ConnOrWaiting::Waiting(make_backoff(), None),
            send_queue: VecDeque::new(),
        };
        Ok(this)
    }
    async fn connect(&mut self) -> Result<&mut WsStream> {
        let mut ws_conn = match &mut self.ws_conn {
            ConnOrWaiting::Conn(_stream) => panic!("called connect while connection still active!"),
            ConnOrWaiting::Waiting(wt, next_sleep_time) => {
                // We implement this retrying logic manually,
                // because our earlier Retryable::retry based implementation is not cancellation safe.
                loop {
                    if let Some(next) = next_sleep_time {
                        tokio::time::sleep_until(*next).await;
                    }
                    *next_sleep_time = Some(Instant::now() + wt.next().unwrap());

                    log::info!("Attempting ws connection to {}", self.url);
                    match connect_async(&self.url).await {
                        Ok((conn, _resp)) => {
                            log::info!("Ws connection to {} established", self.url);
                            break conn;
                        }
                        Err(e) => {
                            fn should_continue(e: &TsError) -> bool {
                                let TsError::Io(e) = e else {
                                    return false;
                                };
                                e.kind() == ErrorKind::ConnectionRefused
                            }
                            if !should_continue(&e) {
                                Err(e)?;
                            }
                        }
                    }
                }
            }
        };
        while let Some(msg) = self.send_queue.pop_front() {
            ws_conn.send(msg).await?;
        }
        Ok(self.ws_conn.insert(ws_conn))
    }
    pub async fn select_next_some(&mut self) -> Result<WsMessage> {
        loop {
            // TODO: figure out how to move this logic into the connect function,
            // all attempts yielded lifetime errors.
            let conn = if let ConnOrWaiting::Conn(conn) = &mut self.ws_conn {
                conn
            } else {
                self.connect().await?
            };
            let msg = match conn.select_next_some().await {
                Ok(v) => v,
                Err(TsError::Io(e)) if e.kind() == ErrorKind::ConnectionReset => {
                    self.ws_conn.reset();
                    continue;
                }
                Err(TsError::Protocol(ProtocolError::ResetWithoutClosingHandshake)) => {
                    self.ws_conn.reset();
                    continue;
                }
                e => e.with_context(|| format!("Error connecting to websocket '{}'", self.url))?,
            };
            if msg.is_close() {
                self.ws_conn.reset();
            }
            return Ok(msg);
        }
    }
    pub async fn send(&mut self, msg: WsMessage) -> Result<()> {
        if let ConnOrWaiting::Conn(conn) = &mut self.ws_conn {
            conn.send(msg).await?;
        } else {
            self.send_queue.push_back(msg);
        }

        Ok(())
    }
}

fn make_backoff() -> ExponentialBackoff {
    ExponentialBuilder::default()
        .with_max_times(usize::MAX)
        .with_min_delay(Duration::from_millis(500))
        .with_max_delay(Duration::from_millis(15_000))
        .build()
}
