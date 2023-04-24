use anyhow::Result;
use libp2p::futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream,
};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A connection closure tolerant web socket context
pub struct WsContext {
    url: String,
    ws_conn: Option<WsStream>,
}

impl WsContext {
    pub async fn new(url: &str) -> Result<Self> {
        let mut this = Self {
            url: url.to_string(),
            ws_conn: None,
        };
        this.connect().await?;
        Ok(this)
    }
    async fn connect(&mut self) -> Result<&mut WsStream> {
        let (ws_conn, _resp) = connect_async(&self.url).await?;
        Ok(self.ws_conn.insert(ws_conn))
    }
    pub async fn select_next_some(&mut self) -> Result<WsMessage> {
        let msg = self.connect().await?.select_next_some().await?;
        if msg.is_close() {
            self.ws_conn = None;
        }
        Ok(msg)
    }
    pub async fn send(&mut self, msg: WsMessage) -> Result<()> {
        self.connect().await?.send(msg).await?;
        Ok(())
    }
}
