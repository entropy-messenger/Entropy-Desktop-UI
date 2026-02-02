use sha2::{Sha256, Digest};
use aes_gcm::KeyInit;
use aes_gcm::aead::Aead;
use rand::Rng;
use crate::protocol;

#[tauri::command]
pub fn crypto_sha256(data: Vec<u8>) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

#[tauri::command]
pub async fn crypto_pbkdf2(password: String, salt: String) -> Result<Vec<u8>, String> {
    tokio::task::spawn_blocking(move || {
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            password.as_bytes(),
            salt.as_bytes(),
            100000,
            &mut key,
        ).map_err(|e| format!("{:?}", e))?;
        Ok(key.to_vec())
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn crypto_encrypt(key: Vec<u8>, plaintext: Vec<u8>) -> Result<String, String> {
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
pub fn crypto_decrypt(key: Vec<u8>, hex_data: String) -> Result<Vec<u8>, String> {
    let combined = hex::decode(hex_data).map_err(|e| e.to_string())?;
    if combined.len() < 12 { return Err("Invalid data".to_string()); }
    
    let nonce = aes_gcm::Nonce::from_slice(&combined[..12]);
    let ciphertext = &combined[12..];
    
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_err(|e| format!("{:?}", e))?;
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| format!("{:?}", e))?;
    
    Ok(plaintext)
}

#[tauri::command]
pub async fn crypto_mine_pow(seed: String, difficulty: u32, context: Option<String>) -> Result<serde_json::Value, String> {
    let ctx = context.unwrap_or_default();
    let seed_clone = seed.clone();
    let ctx_clone = ctx.clone();
    
    let (nonce, hash) = tokio::task::spawn_blocking(move || {
        protocol::mine_pow(&seed_clone, difficulty, &ctx_clone)
    }).await.map_err(|e| e.to_string())??;
    
    Ok(serde_json::json!({
        "seed": seed,
        "nonce": nonce,
        "hash": hash,
        "context": ctx
    }))
}
