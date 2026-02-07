
use rusqlite::Connection;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::mpsc;
use futures_util::{Stream, Sink, SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use sha2::{Sha256, Digest};
use tokio_socks::tcp::Socks5Stream;
use url::Url;
use tokio::time::Duration;
use serde_json::json;
use base64::Engine;
use tokio_tungstenite::tungstenite::Utf8Bytes;
use crate::app_state::{DbState, NetworkState, AudioState, PacedMessage};

const PACING_INTERVAL: u64 = 500;
const MEDIA_INTERVAL: u64 = 10;
const PACKET_SIZE: usize = 1536;
const CHUNK_SIZE: usize = 32 * 1024;

#[tauri::command]
pub async fn start_native_recording(app: AppHandle, state: State<'_, AudioState>) -> Result<String, String> {
    let mut recorder = state.recorder.lock().unwrap();
    recorder.start_recording(app)
}

#[tauri::command]
pub async fn stop_native_recording(state: State<'_, AudioState>) -> Result<Vec<u8>, String> {
    let mut recorder = state.recorder.lock().unwrap();
    recorder.stop_recording()
}

pub fn get_db_filename() -> String {
    if let Ok(profile) = std::env::var("ENTROPY_PROFILE") {
        if !profile.is_empty() {
             return format!("entropy_{}.db", profile);
        }
    }
    "entropy.db".to_string()
}

#[tauri::command]
pub async fn crypto_mine_pow(seed: String, difficulty: u32, context: Option<String>) -> Result<serde_json::Value, String> {
    let ctx = context.unwrap_or_default();
    let target = "0".repeat(difficulty as usize);
    let mut nonce = 0u64;
    
    loop {
        if nonce % 1000 == 0 {
            tokio::task::yield_now().await;
        }

        // PoW format: seed + context + nonce
        let input = format!("{}{}{}", seed, ctx, nonce);
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hex::encode(hasher.finalize());
        
        if result.starts_with(&target) {
            return Ok(serde_json::json!({
                "seed": seed,
                "nonce": nonce,
                "hash": result,
                "context": ctx
            }));
        }
        nonce += 1;
    }
}

#[tauri::command]
pub fn crypto_sha256(data: Vec<u8>) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

#[tauri::command]
pub fn vault_exists(app: AppHandle) -> bool {
    if let Ok(app_data_dir) = app.path().app_data_dir() {
        return app_data_dir.join(get_db_filename()).exists();
    }
    false
}

#[tauri::command]
pub fn init_vault(app: tauri::AppHandle, state: State<'_, DbState>, passphrase: String) -> Result<(), String> {
    // Passphrase is intentionally unused in plaintext mode
    let _ = passphrase; 

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    
    if !app_data_dir.exists() {
        std::fs::create_dir_all(&app_data_dir).map_err(|e| e.to_string())?;
    }

    let db_path = app_data_dir.join(get_db_filename());
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    // Enable WAL mode for better concurrency
    let _ = conn.execute("PRAGMA journal_mode=WAL;", []);

    // Init basic table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS kv_store (
            key TEXT PRIMARY KEY,
            value TEXT
        )",
        [],
    ).map_err(|e: rusqlite::Error| e.to_string())?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS pending_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_type TEXT,
            content BLOB,
            timestamp INTEGER
        )",
        [],
    ).map_err(|e: rusqlite::Error| e.to_string())?;

    let mut db_conn = state.conn.lock().unwrap();
    *db_conn = Some(conn);
    Ok(())
}

#[tauri::command]
pub fn clear_vault(state: State<'_, DbState>) -> Result<(), String> {
    let conn_lock = state.conn.lock().unwrap();
    if let Some(conn) = conn_lock.as_ref() {
        conn.execute("DELETE FROM kv_store;", []).map_err(|e: rusqlite::Error| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn vault_save(state: State<'_, DbState>, key: String, value: String) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value) VALUES (?1, ?2);",
            [key, value],
        )
        .map_err(|e: rusqlite::Error| e.to_string())?;
        Ok(())
    } else {
        Err("Database not initialized".to_string())
    }
}

#[tauri::command]
pub fn vault_load(state: State<'_, DbState>, key: String) -> Result<Option<String>, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let mut stmt = conn
            .prepare("SELECT value FROM kv_store WHERE key = ?1;")
            .map_err(|e: rusqlite::Error| e.to_string())?;
        let mut rows = stmt.query([key]).map_err(|e: rusqlite::Error| e.to_string())?;

        if let Some(row) = rows.next().map_err(|e: rusqlite::Error| e.to_string())? {
            Ok(Some(row.get::<_, String>(0).map_err(|e: rusqlite::Error| e.to_string())?))
        } else {
            Ok(None)
        }
    } else {
        Err("Database not initialized".to_string())
    }
}

#[tauri::command]
pub fn vault_delete(state: State<'_, DbState>, key: String) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        conn.execute("DELETE FROM kv_store WHERE key = ?1;", [key])
            .map_err(|e: rusqlite::Error| e.to_string())?;
        Ok(())
    } else {
        Err("Database not initialized".to_string())
    }
}

#[tauri::command]
pub async fn connect_network(
    app: tauri::AppHandle, 
    state: State<'_, NetworkState>, 
    url: String,
    proxy_url: Option<String>
) -> Result<(), String> {
    let target_url = Url::parse(&url).map_err(|e| e.to_string())?;
    let host = target_url.host_str().ok_or("Invalid host")?;
    let port = target_url.port_or_known_default().ok_or("Invalid port")?;

    let (mut write, mut read) = if let Some(p_url) = proxy_url {
        let proxy_uri = Url::parse(&p_url).map_err(|e| format!("Invalid proxy URL: {}", e))?;
        let proxy_host = proxy_uri.host_str().unwrap_or("127.0.0.1");
        let proxy_port = proxy_uri.port().unwrap_or(9050);
        
        // Simple Socks5 connection
        let socket = Socks5Stream::connect((proxy_host, proxy_port), (host, port))
            .await
            .map_err(|e| format!("Proxy connection failed: {}", e))?;
            
        let (stream, _) = tokio_tungstenite::client_async(&url, socket)
            .await
            .map_err(|e| format!("WebSocket over proxy failed: {}", e))?;
            
        let (w, r) = stream.split();
        (
            Box::new(w) as Box<dyn Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Send + Unpin>,
            Box::new(r) as Box<dyn Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Send + Unpin>
        )
    } else {
        let (stream, _) = connect_async(&url).await.map_err(|e| e.to_string())?;
        let (w, r) = stream.split();
        (
            Box::new(w) as Box<dyn Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Send + Unpin>,
            Box::new(r) as Box<dyn Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Send + Unpin>
        )
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<PacedMessage>();

    {
        let mut sender = state.sender.lock().unwrap();
        *sender = Some(tx.clone());
    }
    
    // Paced Write Loop (Traffic Normalization)
    let app_handle = app.clone();
    
    tokio::spawn(async move {
        let state = app_handle.state::<NetworkState>();
        loop {
            // Priority 1: Check for real messages to send
            let next_msg = {
                let mut q = state.queue.lock().unwrap();
                q.pop_front()
            };

            let is_media;
            let msg_to_send;

            match next_msg {
                Some(paced) => {
                    msg_to_send = paced.msg;
                    is_media = paced.is_media;
                },
                None => {
                    // Drain MPSC if queue is idle
                    while let Ok(msg) = rx.try_recv() {
                        let mut q = state.queue.lock().unwrap();
                        q.push_back(msg);
                    }
                    
                    let mut q = state.queue.lock().unwrap();
                    if let Some(paced) = q.pop_front() {
                        msg_to_send = paced.msg;
                        is_media = paced.is_media;
                    } else {
                        // Truly idle: create a dummy pacing packet
                        let dummy = json!({"type": "dummy_pacing", "p": 0});
                        let mut dummy_str = dummy.to_string();
                        if dummy_str.len() < PACKET_SIZE {
                            dummy_str.push_str(&" ".repeat(PACKET_SIZE - dummy_str.len()));
                        }
                        msg_to_send = Message::Text(Utf8Bytes::from(dummy_str));
                        is_media = false;
                    }
                }
            };

            if let Err(e) = write.send(msg_to_send).await { 
                eprintln!("[Network] WebSocket write failed: {}", e);
                break; 
            }

            let wait_ms = if is_media { MEDIA_INTERVAL } else { PACING_INTERVAL };
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        }

        eprintln!("[Network] Write task terminating. Cleaning up sender state.");
        {
            let state = app_handle.state::<NetworkState>();
            let mut s = state.sender.lock().unwrap();
            if s.is_some() {
                *s = None;
                let _ = app_handle.emit("network-status", "disconnected");
            }
        }
    });
    
    // Read loop
    let app_handle = app.clone();
    tokio::spawn(async move {
        while let Some(res) = read.next().await {
            match res {
                Ok(msg) => {
                    match msg {
                        Message::Text(text) => {
                            let _ = app_handle.emit("network-msg", text.to_string());
                        }
                        Message::Binary(bin) => {
                            let _ = app_handle.emit("network-bin", bin.to_vec());
                        }
                        Message::Close(_) => {
                            break;
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
        
        eprintln!("[Network] Read task terminating.");
        {
            let state = app_handle.state::<NetworkState>();
            let mut s = state.sender.lock().unwrap();
            if s.is_some() {
                *s = None;
                let _ = app_handle.emit("network-status", "disconnected");
            }
        }
    });
    Ok(())
}

#[tauri::command]
pub async fn send_to_network(
    app: AppHandle,
    state: State<'_, NetworkState>, 
    msg: String, 
    is_binary: bool,
    metadata: Option<serde_json::Value> 
) -> Result<(), String> {
    let sender_lock = state.sender.lock().unwrap();
    if let Some(tx) = &*sender_lock {
        if is_binary {
            let bytes = if let Ok(b) = hex::decode(&msg) { b } else { msg.into_bytes() };
            
            if bytes.len() > CHUNK_SIZE {
                if bytes.len() < 64 { return Err("Invalid binary packet: too short for routing hash".into()); }
                
                let (hash_bytes, data_bytes) = bytes.split_at(64);
                let target_hash = String::from_utf8_lossy(hash_bytes).to_string();
                
                let transfer_id = metadata.as_ref()
                    .and_then(|m| m.get("id").and_then(|i| i.as_str()))
                    .unwrap_or("unknown_media")
                    .to_string();
                
                let total_chunks = (data_bytes.len() as f64 / CHUNK_SIZE as f64).ceil() as usize;

                for i in 0..total_chunks {
                    let start = i * CHUNK_SIZE;
                    let end = std::cmp::min(start + CHUNK_SIZE, data_bytes.len());
                    let chunk_slice = &data_bytes[start..end];
                    
                    let fragment_obj = json!({
                        "type": "msg_fragment",
                        "to": target_hash,
                        "fragmentId": transfer_id,
                        "index": i,
                        "total": total_chunks,
                        "data": base64::engine::general_purpose::STANDARD.encode(chunk_slice),
                        "id": format!("{}_{}", transfer_id, i)
                    });
                    
                    tx.send(PacedMessage {
                        msg: Message::Text(Utf8Bytes::from(fragment_obj.to_string())),
                        is_media: true
                    }).map_err(|e: mpsc::error::SendError<PacedMessage>| e.to_string())?;
                }
            } else {
                tx.send(PacedMessage {
                    msg: Message::Binary(bytes.into()),
                    is_media: true
                }).map_err(|e: mpsc::error::SendError<PacedMessage>| e.to_string())?;
            }
        } else {
            let mut padded = msg;
            if padded.len() < PACKET_SIZE {
                padded.push_str(&" ".repeat(PACKET_SIZE - padded.len()));
            }
            tx.send(PacedMessage {
                msg: Message::Text(Utf8Bytes::from(padded)),
                is_media: false
            }).map_err(|e: mpsc::error::SendError<PacedMessage>| e.to_string())?;
        }
        Ok(())
    } else {
        // Queue in persistent outbox if disconnected
        let db_lock = app.state::<DbState>();
        let conn_lock = db_lock.conn.lock().unwrap();
        if let Some(conn) = conn_lock.as_ref() {
            let (msg_type, content) = if is_binary {
                ("binary", hex::decode(&msg).unwrap_or_default())
            } else {
                ("text", msg.into_bytes())
            };
            
            let _ = conn.execute(
                "INSERT INTO pending_outbox (msg_type, content, timestamp) VALUES (?1, ?2, ?3)",
                rusqlite::params![msg_type, content, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()]
            );
        }
        
        Err("Network not connected. Message queued in outbox.".to_string())
    }
}

#[tauri::command]
pub async fn flush_outbox(
    app: AppHandle,
    state: State<'_, NetworkState>
) -> Result<(), String> {
    let sender_lock = state.sender.lock().unwrap();
    if let Some(tx) = &*sender_lock {
        let db_state = app.state::<DbState>();
        let db_lock = db_state.conn.lock().unwrap();
        if let Some(conn) = db_lock.as_ref() {
            let mut stmt = conn.prepare("SELECT id, msg_type, content FROM pending_outbox ORDER BY timestamp ASC").map_err(|e| e.to_string())?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?
                ))
            }).map_err(|e| e.to_string())?;

            for row in rows {
                if let Ok((id, msg_type, content)) = row {
                    let is_media = msg_type == "binary";
                    let msg = if msg_type == "text" {
                        Message::Text(Utf8Bytes::from(String::from_utf8_lossy(&content).to_string()))
                    } else {
                        Message::Binary(content.into())
                    };
                    let _ = tx.send(PacedMessage { msg, is_media });
                    let _ = conn.execute("DELETE FROM pending_outbox WHERE id = ?", [id]);
                }
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub fn nuclear_reset(app: tauri::AppHandle, state: State<'_, DbState>) -> Result<(), String> {
    let mut conn = state.conn.lock().unwrap();
    *conn = None;
    // Release lock before filesystem ops
    drop(conn);

    let filename = get_db_filename();
    let app_dir = app.path().app_data_dir().unwrap();
    let db_path = app_dir.join(&filename);
    let wal_path = app_dir.join(format!("{}-wal", filename));
    let shm_path = app_dir.join(format!("{}-shm", filename));

    if db_path.exists() {
        std::fs::remove_file(db_path).map_err(|e| e.to_string())?;
    }
    if wal_path.exists() {
        let _ = std::fs::remove_file(wal_path);
    }
    if shm_path.exists() {
        let _ = std::fs::remove_file(shm_path);
    }
    Ok(())
}

#[tauri::command]
pub async fn save_file(app: tauri::AppHandle, data: Vec<u8>, filename: String) -> Result<(), String> {
    use std::io::Write;
    
    // Use tauri's path resolver to get downloads folder
    let download_dir = app.path().download_dir().unwrap_or_else(|_| std::env::temp_dir());
    let target_path = download_dir.join(&filename);
    
    println!("[*] Saving file to: {:?}", target_path);
    
    let mut file = std::fs::File::create(&target_path).map_err(|e| e.to_string())?;
    file.write_all(&data).map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
pub async fn export_database(app: tauri::AppHandle, state: State<'_, DbState>, target_path: String) -> Result<(), String> {
    // 1. Checkpoint WAL to main DB file to ensure backup is complete
    {
        let conn_guard = state.conn.lock().unwrap();
        if let Some(conn) = conn_guard.as_ref() {
            // Force checkpoint. TRUNCATE resets the WAL file.
            conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .map_err(|e| format!("Failed to checkpoint DB: {}", e))?;
        }
    }

    let filename = get_db_filename();
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let src_path = app_dir.join(&filename);
    
    if !src_path.exists() {
        return Err("Database file not found".to_string());
    }

    // 2. Clear target first if exists (safe copy)
    if std::path::Path::new(&target_path).exists() {
        std::fs::remove_file(&target_path).map_err(|e| e.to_string())?;
    }

    std::fs::copy(&src_path, &target_path).map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
pub async fn import_database(app: tauri::AppHandle, state: State<'_, DbState>, src_path: String) -> Result<(), String> {
    // 1. Close current connection deeply
    {
        let mut conn = state.conn.lock().unwrap();
        *conn = None;
        drop(conn); // Release lock before filesystem ops
    }

    let backup_path = std::path::Path::new(&src_path);
    if !backup_path.exists() {
        return Err("Selected backup file does not exist".to_string());
    }

    let filename = get_db_filename();
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let dest_path = app_dir.join(&filename);
    let wal_path = app_dir.join(format!("{}-wal", filename));
    let shm_path = app_dir.join(format!("{}-shm", filename));

    // 2. Clean up ALL DB files to prevent WAL headers mismatch
    if dest_path.exists() {
        std::fs::remove_file(&dest_path).map_err(|e| e.to_string())?;
    }
    if wal_path.exists() {
        let _ = std::fs::remove_file(wal_path);
    }
    if shm_path.exists() {
        let _ = std::fs::remove_file(shm_path);
    }

    // 3. Restore
    std::fs::copy(backup_path, &dest_path).map_err(|e| e.to_string())?;

    Ok(())
}
