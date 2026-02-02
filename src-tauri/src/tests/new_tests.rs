use crate::commands;
use crate::protocol;
use rusqlite::Connection;
use serde_json::json;

#[test]
fn test_crypto_sha256() {
    let data = b"hello entropy".to_vec();
    let hash = commands::crypto_sha256(data).unwrap();
    // SHA256 of "hello entropy"
    assert_eq!(hash, "6a122b1e57313e10690bc07bfb5a3163352550a5bb19bab4263d1ce0f5f50939");
}

#[tokio::test]
async fn test_crypto_pbkdf2() {
    let password = "password123".to_string();
    let salt = "somesalt".to_string();
    let key = commands::crypto_pbkdf2(password, salt).await.unwrap();
    assert_eq!(key.len(), 32);
}

#[test]
fn test_crypto_encrypt_decrypt() {
    let key = vec![0u8; 32];
    let plaintext = b"top secret message".to_vec();
    let encrypted_hex = commands::crypto_encrypt(key.clone(), plaintext.clone()).unwrap();
    let decrypted = commands::crypto_decrypt(key, encrypted_hex).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_media_chunking() {
    let key = [1u8; 32];
    let base_nonce = [2u8; 12];
    let data = b"chunk data test".to_vec();
    
    let encrypted = protocol::media::encrypt_media_chunk(&key, &base_nonce, 1, &data).unwrap();
    let decrypted = protocol::media::decrypt_media_chunk(&key, &base_nonce, 1, &encrypted).unwrap();
    
    assert_eq!(decrypted, data);
    
    // Test with different index (should fail or result in different data)
    let wrong_decrypted = protocol::media::decrypt_media_chunk(&key, &base_nonce, 2, &encrypted);
    assert!(wrong_decrypted.is_err());
}

#[test]
fn test_vault_operations() {
    let conn = Connection::open_in_memory().unwrap();
    protocol::types::init_database(&conn).unwrap();
    
    // Test message saving and searching
    let msg = json!({
        "id": "msg1",
        "timestamp": 123456789,
        "content": "Secret rendezvous at midnight",
        "senderHash": "alice123",
        "type": "text",
        "isMine": false,
        "status": "read"
    });
    
    protocol::save_decrypted_message(&conn, "bobhash", &msg).unwrap();
    
    let results = protocol::search_messages(&conn, "rendezvous").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["id"], "msg1");
    
    let no_results = protocol::search_messages(&conn, "missing").unwrap();
    assert_eq!(no_results.len(), 0);
}

#[test]
fn test_self_session_protocol() {
    let conn_a = Connection::open_in_memory().unwrap();
    protocol::types::init_database(&conn_a).unwrap();
    let identity = protocol::generate_new_identity();
    identity.save_to_db(&conn_a).unwrap();
    
    let conn_b = Connection::open_in_memory().unwrap();
    protocol::types::init_database(&conn_b).unwrap();
    identity.save_to_db(&conn_b).unwrap();

    let my_hash = "my_identity_hash"; // Shared identity

    let bundle = json!({
        "identityKey": identity.identity_keys.public_key,
        "pq_identityKey": identity.identity_keys.pq_public_key,
        "signedPreKey": {
            "key_id": identity.signed_pre_key.key_id,
            "publicKey": identity.signed_pre_key.public_key,
            "pq_publicKey": identity.signed_pre_key.pq_public_key,
            "signature": identity.signed_pre_key.signature
        },
        "preKeys": []
    });
    
    // 1. Device A establishes outbound session with "myself" (Device B)
    protocol::establish_outbound_session(&conn_a, my_hash, &bundle).unwrap();
    
    // 2. Device A encrypts a sync message
    let plaintext = "Sync message: Hello from phone".to_string();
    let encrypted = protocol::ratchet_encrypt(&conn_a, my_hash, &plaintext).unwrap();
    
    // 3. Device B (different DB) decrypts it
    let decrypted = protocol::ratchet_decrypt(&conn_b, my_hash, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
    
    // 4. Device B replies (sync back)
    let reply = "Sync: received".to_string();
    let encrypted_reply = protocol::ratchet_encrypt(&conn_b, my_hash, &reply).unwrap();
    
    // 5. Device A decrypts the reply
    let decrypted_reply = protocol::ratchet_decrypt(&conn_a, my_hash, &encrypted_reply).unwrap();
    assert_eq!(decrypted_reply, reply);
}
