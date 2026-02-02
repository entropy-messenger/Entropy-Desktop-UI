use crate::protocol::*;
use rusqlite::Connection;
use std::collections::HashMap;
use sha2::Digest;
use pqcrypto_traits::kem::SecretKey;

fn setup_memory_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_database(&conn).unwrap();
    conn
}

#[test]
fn test_identity_generation() {
    let id = generate_new_identity();
    assert!(!id.identity_keys.public_key.is_empty());
    assert!(!id.identity_keys.pq_public_key.is_empty());
    assert_eq!(id.pre_keys.len(), 10);
}

#[test]
fn test_full_session_flow() {
    let conn_alice = setup_memory_db();
    let conn_bob = setup_memory_db();

    let id_alice = generate_new_identity();
    id_alice.save_to_db(&conn_alice).unwrap();

    let id_bob = generate_new_identity();
    id_bob.save_to_db(&conn_bob).unwrap();

    let bob_bundle = serde_json::json!({
        "registration_id": id_bob.registration_id,
        "identityKey": id_bob.identity_keys.public_key,
        "pq_identityKey": id_bob.identity_keys.pq_public_key,
        "signedPreKey": {
            "keyId": id_bob.signed_pre_key.key_id,
            "publicKey": id_bob.signed_pre_key.public_key,
            "signature": id_bob.signed_pre_key.signature,
            "pq_publicKey": id_bob.signed_pre_key.pq_public_key
        },
        "preKeys": []
    });

    let bob_hash = "bob_identity_hash";
    establish_outbound_session(&conn_alice, bob_hash, &bob_bundle).expect("Alice failed to establish session");

    let plaintext = "Hello Bob, this is a secure message.";
    let msg_alice_1 = ratchet_encrypt(&conn_alice, bob_hash, plaintext).expect("Alice failed to encrypt");
    
    assert!(msg_alice_1.get("body").is_some());
    assert!(msg_alice_1.get("ik").is_some()); 
    assert!(msg_alice_1.get("pq1").is_some());

    let alice_hash = "alice_identity_hash";
    let decrypted_1 = ratchet_decrypt(&conn_bob, alice_hash, &msg_alice_1).expect("Bob failed to decrypt");
    assert_eq!(decrypted_1, plaintext);

    let reply_text = "Hi Alice! Loud and clear.";
    let msg_bob_1 = ratchet_encrypt(&conn_bob, alice_hash, reply_text).expect("Bob failed to encrypt reply");

    let decrypted_reply = ratchet_decrypt(&conn_alice, bob_hash, &msg_bob_1).expect("Alice failed to decrypt reply");
    assert_eq!(decrypted_reply, reply_text);

    let msg_alice_2 = ratchet_encrypt(&conn_alice, bob_hash, "Excellent.").expect("Alice failed 2nd msg");
    let decrypted_2 = ratchet_decrypt(&conn_bob, alice_hash, &msg_alice_2).expect("Bob failed 2nd msg");
    assert_eq!(decrypted_2, "Excellent.");
}

#[test]
fn test_padding() {
    let msg = b"short";
    let padded = pad_message(msg);
    assert!(padded.len() >= 512); 
    let unpadded = unpad_message(&padded).expect("Unpad failed");
    assert_eq!(unpadded, msg);
}

#[test]
fn test_safety_number() {
     let ik1 = "B64Key1";
     let ik2 = "B64Key2";
     let sn1 = calculate_safety_number(ik1, ik2).unwrap();
     let sn2 = calculate_safety_number(ik2, ik1).unwrap(); 
     assert_eq!(sn1, sn2);
     assert_eq!(sn1.len(), 35); 
}

#[test]
fn test_persistence_reopen() {
    let path = "./test_vault.db";
    let _ = std::fs::remove_file(path);

    {
        let conn = Connection::open(path).unwrap();
        init_database(&conn).unwrap();
        let id = generate_new_identity();
        id.save_to_db(&conn).unwrap();
    } 

    {
        let conn = Connection::open(path).unwrap();
        let id_loaded = ProtocolIdentity::load_from_db(&conn).unwrap().expect("Failed to load identity");
        assert!(!id_loaded.identity_keys.public_key.is_empty());
    }
    let _ = std::fs::remove_file(path);
}

#[test]
fn test_out_of_order_chaining() {
    let conn_alice = setup_memory_db();
    let conn_bob = setup_memory_db();

    let id_alice = generate_new_identity();
    id_alice.save_to_db(&conn_alice).unwrap();
    let id_bob = generate_new_identity();
    id_bob.save_to_db(&conn_bob).unwrap();

    let bob_bundle = serde_json::json!({
        "identityKey": id_bob.identity_keys.public_key,
        "signedPreKey": {
            "keyId": id_bob.signed_pre_key.key_id,
            "publicKey": id_bob.signed_pre_key.public_key,
            "signature": id_bob.signed_pre_key.signature,
            "pq_publicKey": id_bob.signed_pre_key.pq_public_key
        },
        "preKeys": [],
        "pq_identityKey": id_bob.identity_keys.pq_public_key
    }); 
    establish_outbound_session(&conn_alice, "bob", &bob_bundle).unwrap();

    let msg0 = ratchet_encrypt(&conn_alice, "bob", "Init").unwrap();
    let msg1 = ratchet_encrypt(&conn_alice, "bob", "Message 1").unwrap();
    let msg2 = ratchet_encrypt(&conn_alice, "bob", "Message 2").unwrap();
    let msg3 = ratchet_encrypt(&conn_alice, "bob", "Message 3").unwrap();

    let dec0 = ratchet_decrypt(&conn_bob, "alice", &msg0).unwrap();
    assert_eq!(dec0, "Init");

    let dec3 = ratchet_decrypt(&conn_bob, "alice", &msg3).unwrap();
    assert_eq!(dec3, "Message 3");

    let state = SessionState::load_from_db(&conn_bob, "alice").unwrap().unwrap();
    assert_eq!(state.skipped_message_keys.len(), 2);

    let dec1 = ratchet_decrypt(&conn_bob, "alice", &msg1).unwrap();
    assert_eq!(dec1, "Message 1");
    
    let dec2 = ratchet_decrypt(&conn_bob, "alice", &msg2).unwrap();
    assert_eq!(dec2, "Message 2");

    let state_final = SessionState::load_from_db(&conn_bob, "alice").unwrap().unwrap();
    assert_eq!(state_final.skipped_message_keys.len(), 0);
}

#[test]
fn test_continuity_lock_history_fork() {
    let conn_alice = setup_memory_db();
    let conn_bob = setup_memory_db();

    let id_alice = generate_new_identity();
    id_alice.save_to_db(&conn_alice).unwrap();
    let id_bob = generate_new_identity();
    id_bob.save_to_db(&conn_bob).unwrap();

    let bob_bundle = serde_json::json!({
        "identityKey": id_bob.identity_keys.public_key,
        "signedPreKey": {
            "keyId": id_bob.signed_pre_key.key_id,
            "publicKey": id_bob.signed_pre_key.public_key,
            "signature": id_bob.signed_pre_key.signature,
            "pq_publicKey": id_bob.signed_pre_key.pq_public_key
        },
        "preKeys": [],
        "pq_identityKey": id_bob.identity_keys.pq_public_key
    }); 
    establish_outbound_session(&conn_alice, "bob", &bob_bundle).unwrap();

    let msg0 = ratchet_encrypt(&conn_alice, "bob", "Hello There").unwrap();
    ratchet_decrypt(&conn_bob, "alice", &msg0).unwrap();

    let msg_bob = ratchet_encrypt(&conn_bob, "alice", "General Kenobi").unwrap();
    ratchet_decrypt(&conn_alice, "bob", &msg_bob).unwrap();
    
    {
        let mut state_alice = SessionState::load_from_db(&conn_alice, "bob").unwrap().unwrap();
        state_alice.last_recv_hash = Some("HASH_OF_GHOST_MESSAGE".to_string());
        state_alice.save_to_db(&conn_alice, "bob").unwrap();
    }

    let msg_alice_2 = ratchet_encrypt(&conn_alice, "bob", "You are a bold one").unwrap();
    let result = ratchet_decrypt(&conn_bob, "alice", &msg_alice_2);

    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("CONTINUITY_BREAK"));
}

#[test]
fn test_vault_portability_simulation() {
    let path_src = "./test_port_src.db";
    let path_dst = "./test_port_dst.db";
    let _ = std::fs::remove_file(path_src);
    let _ = std::fs::remove_file(path_dst);

    let ik_peer;

    {
        let conn = Connection::open(path_src).unwrap();
        init_database(&conn).unwrap();
        let id = generate_new_identity();
        id.save_to_db(&conn).unwrap();
        
        let id_peer = generate_new_identity();
        ik_peer = id_peer.identity_keys.public_key.clone();

        let bundle = serde_json::json!({
            "identityKey": id_peer.identity_keys.public_key,
            "pq_identityKey": id_peer.identity_keys.pq_public_key,
            "registrationId": id_peer.registration_id,
            "signedPreKey": { 
                "keyId": id_peer.signed_pre_key.key_id, 
                "publicKey": id_peer.signed_pre_key.public_key, 
                "pq_publicKey": id_peer.signed_pre_key.pq_public_key, 
                "signature": id_peer.signed_pre_key.signature 
            },
            "preKeys": []
        });
        establish_outbound_session(&conn, "peer", &bundle).unwrap();
    }

    std::fs::copy(path_src, path_dst).unwrap();

    {
        let conn = Connection::open(path_dst).unwrap();
        let id_loaded = ProtocolIdentity::load_from_db(&conn).unwrap().expect("ID lost");
        let session = SessionState::load_from_db(&conn, "peer").unwrap().expect("Session lost");
        
        assert!(!id_loaded.identity_keys.public_key.is_empty());
        assert_eq!(session.remote_identity_key, Some(ik_peer));
    }

    let _ = std::fs::remove_file(path_src);
    let _ = std::fs::remove_file(path_dst);
}

#[test]
fn test_group_messaging_flow() {
    let conn = setup_memory_db();
    
    let mut alice_gs = GroupState {
        group_id: "test_group".to_string(),
        my_sender_key: Some(create_group_sender_key()),
        member_sender_keys: HashMap::new(),
        members: vec![],
    };

    let dist_msg = create_group_distribution_message(&alice_gs).unwrap();

    let mut bob_gs = GroupState {
        group_id: "test_group".to_string(),
        my_sender_key: Some(create_group_sender_key()),
        member_sender_keys: HashMap::new(),
        members: vec![],
    };
    
    let alice_sk = SenderKey {
        key_id: dist_msg["key_id"].as_u64().unwrap() as u32,
        chain_key: dist_msg["chain_key"].as_str().unwrap().to_string(),
        signature_key_private: "".to_string(), 
        signature_key_public: dist_msg["signature_key_public"].as_str().unwrap().to_string(),
    };
    bob_gs.member_sender_keys.insert("alice_hash".to_string(), alice_sk);

    let plaintext = "Hello Group!";
    let enc_msg = group_encrypt(&conn, &mut alice_gs, plaintext).unwrap();

    let dec_msg = group_decrypt(&mut bob_gs, "alice_hash", &enc_msg).unwrap();
    assert_eq!(dec_msg, plaintext);

    let enc_msg_2 = group_encrypt(&conn, &mut alice_gs, "Second Message").unwrap();
    let dec_msg_2 = group_decrypt(&mut bob_gs, "alice_hash", &enc_msg_2).unwrap();
    assert_eq!(dec_msg_2, "Second Message");
}

#[test]
fn test_sealed_sender_hybrid_flow() {
    let id_recipient = generate_new_identity();
    
    let recipient_sk_bytes = decode_b64(&id_recipient.identity_keys.private_key).unwrap();
    let recipient_sk = ed25519_priv_to_x25519(&recipient_sk_bytes).unwrap();
    
    let recipient_pq_sk = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(&decode_b64(&id_recipient.identity_keys.pq_private_key).unwrap()).unwrap();

    let sender_identity = "alice_identity_b64";
    let message_body = serde_json::json!({"action": "ping"});

    let sealed = seal_sender(
        message_body.clone(),
        sender_identity,
        &X25519PublicKey::from(ed25519_pub_to_x25519(&decode_b64(&id_recipient.identity_keys.public_key).unwrap()).unwrap()),
        &id_recipient.identity_keys.pq_public_key
    ).unwrap();

    let (unsealed_sender, unsealed_msg) = unseal_sender(&sealed, &recipient_sk, &recipient_pq_sk).unwrap();

    assert_eq!(unsealed_sender, sender_identity);
    assert_eq!(unsealed_msg, message_body);
}

#[test]
fn test_media_encryption_integrity() {
    let conn = setup_memory_db();
    let original_data = b"Some secret image data here";
    let file_name = "secret.png";
    let file_type = "image/png";

    let (ct, bundle) = encrypt_media(&conn, original_data, file_name, file_type).unwrap();
    assert_ne!(ct, original_data);

    let decrypted = decrypt_media(&conn, &ct, &bundle).unwrap();
    assert_eq!(decrypted, original_data);
    assert_eq!(bundle.file_name, file_name);
    assert_eq!(bundle.file_type, file_type);

    let mut tampered_ct = ct.clone();
    tampered_ct[0] ^= 0xFF;
    let result = decrypt_media(&conn, &tampered_ct, &bundle);
    assert!(result.is_err());
}

#[test]
fn test_pending_message_persistence_logic() {
    let conn = setup_memory_db();
    let msg = PendingMessage {
        id: "msg_1".to_string(),
        recipient_hash: "bob".to_string(),
        body: "{}".to_string(),
        timestamp: 123456789,
        retries: 0,
    };

    save_pending_message(&conn, &msg).unwrap();
    let pending = get_pending_messages(&conn).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, "msg_1");

    remove_pending_message(&conn, "msg_1").unwrap();
    let pending_empty = get_pending_messages(&conn).unwrap();
    assert_eq!(pending_empty.len(), 0);
}

#[test]
fn test_pow_mining_logic() {
    let seed = "test_seed";
    let context = "test_context";
    let difficulty = 2; 
    
    let (nonce, hash) = mine_pow(seed, difficulty, context).unwrap();
    assert!(hash.starts_with("00"));
    
    let mut hasher = sha2::Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(context.as_bytes());
    hasher.update(nonce.to_string().as_bytes());
    let result = hasher.finalize();
    assert_eq!(hex::encode(result), hash);
}

#[test]
fn test_pre_key_replenishment_cap() {
    let mut identity = generate_new_identity();
    assert_eq!(identity.pre_keys.len(), 10);

    // Replenish with 120 more (Total 130) -> should cap at 100
    identity.replenish_pre_keys(120);
    assert_eq!(identity.pre_keys.len(), 100);

    // Oldest key should be id 31 (130 - 100 + 1 if IDs are sequential from 1)
    // Actually generate_new_identity starts at 1. 
    // Initial: 1..10
    // Replenish 120: new IDs are 11..130
    // Total 130. Drain 30. Remaining: 31..130
    assert_eq!(identity.pre_keys[0].key_id, 31);
    assert_eq!(identity.pre_keys[99].key_id, 130);
}
