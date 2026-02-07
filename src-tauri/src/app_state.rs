use rusqlite::Connection;
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::Message;

use crate::audio::AudioRecorder;

use std::collections::VecDeque;

pub struct DbState {
    pub conn: Mutex<Option<Connection>>,
}

pub struct PacedMessage {
    pub msg: Message,
    pub is_media: bool,
}

pub struct NetworkState {
    pub queue: Mutex<VecDeque<PacedMessage>>,
    pub sender: Mutex<Option<mpsc::UnboundedSender<PacedMessage>>>, 
}

pub struct AudioState {
    pub recorder: Mutex<AudioRecorder>,
}
