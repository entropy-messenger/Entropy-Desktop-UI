
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use keyring::Entry;
use rusqlite::Connection;
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, State,
};
use tokio::sync::mpsc;
use futures_util::{stream::Stream, Sink, SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use sha2::{Sha256, Digest};
use tokio_socks::tcp::Socks5Stream;
use url::Url;
mod protocol;
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use rand::Rng;
use pqcrypto_traits::kem::SecretKey as _; 

struct DbState {
    conn: Mutex<Option<Connection>>,
}

#[tauri::command]
fn protocol_establish_session(
    state: State<'_, DbState>,
    remote_hash: String,
    bundle: serde_json::Value
) -> Result<(), String> {
    let conn_lock = state.conn.lock().unwrap();
    if let Some(conn) = conn_lock.as_ref() {
        protocol::establish_outbound_session(conn, &remote_hash, &bundle)
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
fn protocol_encrypt(
    state: State<'_, DbState>,
    remote_hash: String,
    plaintext: String
) -> Result<serde_json::Value, String> {
    let conn_lock = state.conn.lock().unwrap();
    if let Some(conn) = conn_lock.as_ref() {
        protocol::ratchet_encrypt(conn, &remote_hash, &plaintext)
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
fn protocol_decrypt(
    state: State<'_, DbState>,
    remote_hash: String,
    msg_obj: serde_json::Value
) -> Result<String, String> {
    let conn_lock = state.conn.lock().unwrap();
    if let Some(conn) = conn_lock.as_ref() {
        protocol::ratchet_decrypt(conn, &remote_hash, &msg_obj)
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
fn protocol_get_safety_number(me_ik: String, peer_ik: String) -> Result<String, String> {
    protocol::calculate_safety_number(&me_ik, &peer_ik)
}

#[tauri::command]
fn protocol_init(state: State<'_, DbState>) -> Result<serde_json::Value, String> {
    let conn_lock = state.conn.lock().unwrap();
    if let Some(conn) = conn_lock.as_ref() {
        let identity = if let Some(identity) = protocol::ProtocolIdentity::load_from_db(conn)? {
            identity
        } else {
            let identity = protocol::generate_new_identity();
            identity.save_to_db(conn)?;
            identity
        };

        
        Ok(serde_json::json!({
            "registration_id": identity.registration_id,
            "identity_key": identity.identity_keys.public_key,
            "pq_identity_key": identity.identity_keys.pq_public_key,
            "signed_pre_key": {
                "key_id": identity.signed_pre_key.key_id,
                "public_key": identity.signed_pre_key.public_key,
                "signature": identity.signed_pre_key.signature,
                "pq_public_key": identity.signed_pre_key.pq_public_key
            },
            "pre_keys": identity.pre_keys.iter().map(|pk| serde_json::json!({
                "key_id": pk.key_id,
                "public_key": pk.public_key
            })).collect::<Vec<_>>()
        }))
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
fn protocol_sign(state: State<'_, DbState>, message: String) -> Result<String, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        protocol::sign_message(conn, message.as_bytes())
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
fn protocol_replenish_pre_keys(state: State<'_, DbState>, count: u32) -> Result<serde_json::Value, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let mut identity = protocol::ProtocolIdentity::load_from_db(conn)?.ok_or("No identity")?;
        identity.replenish_pre_keys(count);
        identity.save_to_db(conn)?;
        Ok(serde_json::json!({
            "pre_keys": identity.pre_keys.iter().rev().take(count as usize).map(|pk| serde_json::json!({
                "key_id": pk.key_id,
                "public_key": pk.public_key
            })).collect::<Vec<_>>()
        }))
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_verify_session(state: State<'_, DbState>, remote_hash: String, is_verified: bool) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        protocol::verify_session(conn, &remote_hash, is_verified)
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_secure_vacuum(state: State<'_, DbState>) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        conn.execute("VACUUM;", []).map_err(|e| e.to_string())?;
        Ok(())
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_encrypt_sealed(
    state: State<'_, DbState>,
    remote_public_identity_key: String,
    remote_pq_public_identity_key: String,
    message_body: serde_json::Value
) -> Result<serde_json::Value, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let identity = protocol::ProtocolIdentity::load_from_db(conn)?.ok_or("No identity")?;
        
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&protocol::decode_b64(&remote_public_identity_key)?);
        let recipient_pk = protocol::X25519PublicKey::from(pk_bytes);

        protocol::seal_sender(message_body, &identity.identity_keys.public_key, &recipient_pk, &remote_pq_public_identity_key)
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_decrypt_sealed(
    state: State<'_, DbState>,
    sealed_obj: serde_json::Value
) -> Result<serde_json::Value, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let identity = protocol::ProtocolIdentity::load_from_db(conn)?.ok_or("No identity")?;
        
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&protocol::decode_b64(&identity.identity_keys.private_key)?);
        let my_sk = protocol::StaticSecret::from(sk_bytes);

        let my_pq_sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(&protocol::decode_b64(&identity.identity_keys.pq_private_key)?).map_err(|_| "Invalid PQ SK")?;

        let (sender, message) = protocol::unseal_sender(&sealed_obj, &my_sk, &my_pq_sk)?;
        Ok(serde_json::json!({
            "sender": sender,
            "message": message
        }))
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn crypto_sha256(data: String) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

#[tauri::command]
fn crypto_pbkdf2(password: String, salt: String) -> Result<Vec<u8>, String> {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        password.as_bytes(),
        salt.as_bytes(),
        100000,
        &mut key,
    ).map_err(|e| format!("{:?}", e))?;
    Ok(key.to_vec())
}

#[tauri::command]
fn crypto_encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> Result<String, String> {
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_err(|e| format!("{:?}", e))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, plaintext.as_slice()).map_err(|e| format!("{:?}", e))?;
    
    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    
    Ok(hex::encode(combined))
}

#[tauri::command]
fn crypto_decrypt(key: Vec<u8>, hex_data: String) -> Result<Vec<u8>, String> {
    let combined = hex::decode(hex_data).map_err(|e| e.to_string())?;
    if combined.len() < 12 { return Err("Invalid data".to_string()); }
    
    let nonce = aes_gcm::Nonce::from_slice(&combined[..12]);
    let ciphertext = &combined[12..];
    
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_err(|e| format!("{:?}", e))?;
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| format!("{:?}", e))?;
    
    Ok(plaintext)
}

#[tauri::command]
fn crypto_mine_pow(seed: String, difficulty: u32, context: Option<String>) -> Result<serde_json::Value, String> {
    let ctx = context.unwrap_or_default();
    let (nonce, hash) = protocol::mine_pow(&seed, difficulty, &ctx)?;
    
    Ok(serde_json::json!({
        "seed": seed,
        "nonce": nonce,
        "hash": hash,
        "context": ctx
    }))
}

#[tauri::command]
fn protocol_encrypt_media(
    state: State<'_, DbState>,
    data: Vec<u8>,
    file_name: String,
    file_type: String
) -> Result<serde_json::Value, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let (ct, bundle) = protocol::encrypt_media(conn, &data, &file_name, &file_type)?;
        Ok(serde_json::json!({
            "ciphertext": hex::encode(ct),
            "bundle": bundle
        }))
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_create_group_distribution(state: State<'_, DbState>, group_id: String) -> Result<serde_json::Value, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let mut stmt = conn.prepare("SELECT state FROM groups WHERE group_id = ?1;").map_err(|e| e.to_string())?;
        let row: String = stmt.query_row([&group_id], |r| r.get(0)).map_err(|e| e.to_string())?;
        let gs: protocol::GroupState = serde_json::from_str(&row).map_err(|e| e.to_string())?;
        protocol::create_group_distribution_message(&gs)
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_group_init(state: State<'_, DbState>, group_id: String) -> Result<serde_json::Value, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let gs = protocol::GroupState {
            group_id: group_id.clone(),
            my_sender_key: Some(protocol::create_group_sender_key()),
            member_sender_keys: std::collections::HashMap::new(),
        };
        gs.save_to_db(conn)?;
        let dist = protocol::create_group_distribution_message(&gs)?;
        Ok(dist)
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_group_encrypt(state: State<'_, DbState>, group_id: String, plaintext: String) -> Result<serde_json::Value, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let mut gs = protocol::GroupState::load_from_db(conn, &group_id)?.ok_or("Group not found")?;
        let res = protocol::group_encrypt(conn, &mut gs, &plaintext)?;
        gs.save_to_db(conn)?;
        Ok(res)
    } else { Err("Vault not initialized".to_string()) }
}


#[tauri::command]
fn protocol_group_decrypt(state: State<'_, DbState>, group_id: String, sender_hash: String, msg_obj: serde_json::Value) -> Result<String, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let mut gs = protocol::GroupState::load_from_db(conn, &group_id)?.ok_or("Group not found")?;
        let res = protocol::group_decrypt(&mut gs, &sender_hash, &msg_obj)?;
        gs.save_to_db(conn)?;
        Ok(res)
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_process_group_distribution(state: State<'_, DbState>, sender_hash: String, dist_obj: serde_json::Value) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let group_id = dist_obj["group_id"].as_str().ok_or("Missing group_id")?;
        let mut gs = protocol::GroupState::load_from_db(conn, group_id)?.unwrap_or_else(|| protocol::GroupState {
            group_id: group_id.to_string(),
            my_sender_key: None,
            member_sender_keys: std::collections::HashMap::new(),
        });
        
        let sk = protocol::SenderKey {
            key_id: dist_obj["key_id"].as_u64().ok_or("Missing key_id")? as u32,
            chain_key: dist_obj["chain_key"].as_str().ok_or("Missing chain_key")?.to_string(),
            signature_key_private: "".to_string(), 
            signature_key_public: dist_obj["signature_key_public"].as_str().ok_or("Missing signature_key_public")?.to_string(),
        };
        
        gs.member_sender_keys.insert(sender_hash, sk);
        gs.save_to_db(conn)?;
        Ok(())
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_decrypt_media(
    state: State<'_, DbState>,
    hex_data: String,
    bundle: protocol::MediaKeyBundle
) -> Result<Vec<u8>, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let ct = hex::decode(hex_data).map_err(|e| e.to_string())?;
        protocol::decrypt_media(conn, &ct, &bundle)
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_get_pending(state: State<'_, DbState>) -> Result<Vec<protocol::PendingMessage>, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        protocol::get_pending_messages(conn)
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_remove_pending(state: State<'_, DbState>, id: String) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        protocol::remove_pending_message(conn, &id)
    } else { Err("Vault not initialized".to_string()) }
}

#[tauri::command]
fn protocol_save_pending(state: State<'_, DbState>, msg: protocol::PendingMessage) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        protocol::save_pending_message(conn, &msg)
    } else { Err("Vault not initialized".to_string()) }
}

struct NetworkState {
    sender: Mutex<Option<mpsc::UnboundedSender<Message>>>,
}


#[tauri::command]
fn store_secret(app: tauri::AppHandle, key: String, value: String) -> Result<(), String> {
    
    if let Ok(entry) = Entry::new("Entropy", &key) {
        let _ = entry.set_password(&value);
    }

    
    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    if !app_data_dir.exists() {
        std::fs::create_dir_all(&app_data_dir).map_err(|e| e.to_string())?;
    }
    let secret_path = app_data_dir.join(format!("{}.secret", key));
    std::fs::write(secret_path, value).map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
fn get_secret(app: tauri::AppHandle, key: String) -> Result<String, String> {
    
    if let Ok(entry) = Entry::new("Entropy", &key) {
        if let Ok(pass) = entry.get_password() {
            return Ok(pass);
        }
    }
    
    
    if let Ok(entry) = Entry::new("io.entropy.messenger", &key) {
        if let Ok(pass) = entry.get_password() {
            return Ok(pass);
        }
    }

    
    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let secret_path = app_data_dir.join(format!("{}.secret", key));
    if secret_path.exists() {
        return std::fs::read_to_string(secret_path).map_err(|e| e.to_string());
    }

    Err("Secret not found".to_string())
}

#[tauri::command]
fn init_vault(app: tauri::AppHandle, state: State<'_, DbState>, passphrase: String) -> Result<(), String> {
    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    
    if !app_data_dir.exists() {
        std::fs::create_dir_all(&app_data_dir).map_err(|e| e.to_string())?;
    }

    let db_path = app_data_dir.join("vault.db");
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    if let Err(e) = conn.pragma_update(None, "key", passphrase) {
        return Err(format!("Failed to set encryption key: {}", e));
    }

    protocol::init_database(&conn)?;

    let mut db_conn = state.conn.lock().unwrap();
    *db_conn = Some(conn);
    Ok(())
}

#[tauri::command]
fn protocol_export_vault(app: tauri::AppHandle) -> Result<Vec<u8>, String> {
    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    let db_path = app_data_dir.join("vault.db");
    if !db_path.exists() { return Err("Vault does not exist".to_string()); }
    std::fs::read(db_path).map_err(|e| e.to_string())
}

#[tauri::command]
fn protocol_import_vault(app: tauri::AppHandle, state: State<'_, DbState>, bytes: Vec<u8>) -> Result<(), String> {
    
    {
        let mut lock = state.conn.lock().unwrap();
        *lock = None;
    }

    
    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    if !app_data_dir.exists() {
        std::fs::create_dir_all(&app_data_dir).map_err(|e| e.to_string())?;
    }
    let db_path = app_data_dir.join("vault.db");
    std::fs::write(db_path, bytes).map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
fn protocol_save_vault_to_path(path: String, bytes: Vec<u8>) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}

#[tauri::command]
fn protocol_read_vault_from_path(path: String) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| e.to_string())
}

#[tauri::command]
fn clear_vault(state: State<'_, DbState>) -> Result<(), String> {
    let conn_lock = state.conn.lock().unwrap();
    if let Some(conn) = conn_lock.as_ref() {
        conn.execute("DELETE FROM vault;", []).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn vault_save(state: State<'_, DbState>, key: String, value: String) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        conn.execute(
            "INSERT OR REPLACE INTO vault (key, value) VALUES (?1, ?2);",
            [key, value],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
fn vault_load(state: State<'_, DbState>, key: String) -> Result<Option<String>, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let mut stmt = conn
            .prepare("SELECT value FROM vault WHERE key = ?1;")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt.query([key]).map_err(|e| e.to_string())?;

        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            Ok(Some(row.get(0).map_err(|e| e.to_string())?))
        } else {
            Ok(None)
        }
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
async fn connect_network(
    app: tauri::AppHandle, 
    state: State<'_, NetworkState>, 
    url: String,
    proxy_url: Option<String>
) -> Result<(), String> {
    println!("Network: Connecting to {}...", url);
    
    let target_url = Url::parse(&url).map_err(|e| e.to_string())?;
    let host = target_url.host_str().ok_or("Invalid host")?;
    let port = target_url.port_or_known_default().ok_or("Invalid port")?;

    let (mut write, mut read) = if let Some(p_url) = proxy_url {
        println!("Network: Routing through SOCKS5 proxy: {}", p_url);
        let proxy_uri = Url::parse(&p_url).map_err(|e| format!("Invalid proxy URL: {}", e))?;
        let proxy_host = proxy_uri.host_str().unwrap_or("127.0.0.1");
        let proxy_port = proxy_uri.port().unwrap_or(9050);
        
        
        
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

    println!("Network: Connected successfully.");
    
    
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    {
        let mut sender = state.sender.lock().unwrap();
        *sender = Some(tx);
    }

    
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write.send(msg).await {
                println!("Network: Write error: {}", e);
                break;
            }
        }
        println!("Network: Write task terminated.");
    });

    
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
                            println!("Network: Server closed connection.");
                            break;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    println!("Network: Read error: {}", e);
                    break;
                }
            }
        }
        println!("Network: Connection lost. Emitting disconnect.");
        let _ = app_handle.emit("network-status", "disconnected");
    });

    
    let app_h = app.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            
            let db_state = app_h.state::<DbState>();
            let network_state = app_h.state::<NetworkState>();

            let pending = {
                let lock = db_state.conn.lock().unwrap();
                if let Some(conn) = lock.as_ref() {
                    protocol::get_pending_messages(conn).unwrap_or_default()
                } else { vec![] }
            };

            if pending.is_empty() { continue; }

            let sender_opt = {
                let lock = network_state.sender.lock().unwrap();
                lock.clone()
            };

            if let Some(tx) = sender_opt {
                for msg in pending {
                    if tx.send(Message::Text(msg.body.into())).is_ok() {
                         let lock = db_state.conn.lock().unwrap();
                         if let Some(conn) = lock.as_ref() {
                             let _ = protocol::remove_pending_message(conn, &msg.id);
                         }
                    }
                }
            } else {
                break;
            }
        }
    });

    Ok(())
}

#[tauri::command]
fn send_to_network(state: State<'_, NetworkState>, msg: String, is_binary: bool) -> Result<(), String> {
    let sender_lock = state.sender.lock().unwrap();
    if let Some(tx) = &*sender_lock {
        let message = if is_binary {
            let bytes = hex::decode(msg).map_err(|e| e.to_string())?;
            Message::Binary(bytes.into())
        } else {
            Message::Text(msg.into())
        };
        tx.send(message).map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("Network not connected".to_string())
    }
}

#[tauri::command]
fn dump_vault(state: State<'_, DbState>) -> Result<std::collections::HashMap<String, String>, String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        let mut stmt = conn.prepare("SELECT key, value FROM vault;").map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).map_err(|e| e.to_string())?;

        let mut data = std::collections::HashMap::new();
        for row in rows {
            let (k, v) = row.map_err(|e| e.to_string())?;
            data.insert(k, v);
        }
        Ok(data)
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
fn restore_vault(state: State<'_, DbState>, data: std::collections::HashMap<String, String>) -> Result<(), String> {
    let lock = state.conn.lock().unwrap();
    if let Some(conn) = lock.as_ref() {
        for (k, v) in data {
            conn.execute(
                "INSERT OR REPLACE INTO vault (key, value) VALUES (?1, ?2);",
                [&k, &v],
            ).map_err(|e| e.to_string())?;
        }
        Ok(())
    } else {
        Err("Vault not initialized".to_string())
    }
}

#[tauri::command]
fn nuclear_reset(app: tauri::AppHandle, state: State<'_, DbState>) -> Result<(), String> {
    
    if let Ok(mut conn) = state.conn.lock() {
        *conn = None;
    }

    let app_data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    
    
    let _ = protocol::secure_nuke_database(&app_data_dir.join("vault.db"));
    let _ = protocol::secure_nuke_database(&app_data_dir.join("entropy_vault_salt.secret"));
    
    
    let _ = Entry::new("Entropy", "entropy_vault_salt").map(|entry| entry.delete_credential());
    
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .manage(DbState {
            conn: Mutex::new(None),
        })
        .manage(NetworkState {
            sender: Mutex::new(None),
        })
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            store_secret,
            get_secret,
            init_vault,
            vault_save,
            vault_load,
            dump_vault,
            restore_vault,
            crypto_sha256,
            crypto_pbkdf2,
            crypto_encrypt,
            crypto_decrypt,
            protocol_init,
            protocol_get_safety_number,
            protocol_establish_session,
            protocol_encrypt,
            protocol_decrypt,
            protocol_encrypt_media,
            protocol_decrypt_media,
            protocol_get_pending,
            protocol_save_pending,
            protocol_remove_pending,
            protocol_replenish_pre_keys,
            protocol_verify_session,
            protocol_secure_vacuum,
            protocol_encrypt_sealed,
            protocol_decrypt_sealed,
            protocol_create_group_distribution,
            protocol_group_init,
            protocol_group_encrypt,
            protocol_group_decrypt,
            protocol_process_group_distribution,
            connect_network,
            send_to_network,
            nuclear_reset,
            crypto_mine_pow,
            clear_vault,
            protocol_sign,
            protocol_export_vault,
            protocol_import_vault,
            protocol_save_vault_to_path,
            protocol_read_vault_from_path
        ])
        .setup(|app| {
            let quit_i = MenuItem::with_id(app, "quit", "Quit Entropy", true, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Show Window", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        app.exit(0);
                    }
                    "show" => {
                        let window = app.get_webview_window("main").unwrap();
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { .. } = event {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
