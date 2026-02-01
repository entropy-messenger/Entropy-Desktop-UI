use ed25519_dalek::{Keypair, Signer, PublicKey, SecretKey};
pub use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use sha2::{Sha256, Sha512, Digest};
use rand::{RngCore, thread_rng};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use curve25519_dalek::edwards::CompressedEdwardsY;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as PQPubKey, SecretKey as PQSecretKey, Ciphertext as PQCiphertext, SharedSecret as PQSharedSecret};



#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityKeys {
    pub public_key: String,
    pub private_key: String,
    pub pq_public_key: String,
    pub pq_private_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreKey {
    pub key_id: u32,
    pub public_key: String,
    pub private_key: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub public_key: String,
    pub private_key: String,
    pub signature: String,
    pub pq_public_key: String,
    pub pq_private_key: String,
}



#[derive(Serialize, Deserialize, Clone)]
pub struct ProtocolIdentity {
    pub registration_id: u32,
    pub identity_keys: IdentityKeys,
    pub signed_pre_key: SignedPreKey,
    pub pre_keys: Vec<PreKey>,
}

pub fn init_database(conn: &Connection) -> Result<(), String> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS vault (key TEXT PRIMARY KEY, value TEXT);",
        [],
    ).map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS pending_messages (id TEXT PRIMARY KEY, recipient_hash TEXT, body TEXT, timestamp INTEGER, retries INTEGER);",
        [],
    ).map_err(|e| e.to_string())?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS groups (group_id TEXT PRIMARY KEY, state TEXT);",
        [],
    ).map_err(|e| e.to_string())?;

    Ok(())
}

impl ProtocolIdentity {
    pub fn save_to_db(&self, conn: &Connection) -> Result<(), String> {
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO vault (key, value) VALUES ('protocol_identity', ?1);",
            params![json],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_from_db(conn: &Connection) -> Result<Option<Self>, String> {
        let mut stmt = conn.prepare("SELECT value FROM vault WHERE key = 'protocol_identity';").map_err(|e| e.to_string())?;
        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let json: String = row.get(0).map_err(|e| e.to_string())?;
            let identity: ProtocolIdentity = serde_json::from_str(&json).map_err(|e| e.to_string())?;
            Ok(Some(identity))
        } else {
            Ok(None)
        }
    }

    pub fn replenish_pre_keys(&mut self, count: u32) {
        let mut rng = thread_rng();
        let start_id = self.pre_keys.iter().map(|k| k.key_id).max().unwrap_or(0) + 1;
        
        for i in 0..count {
            let mut pk_bytes = [0u8; 32];
            rng.fill_bytes(&mut pk_bytes);
            let pk_secret = StaticSecret::from(pk_bytes);
            let pk_public = X25519PublicKey::from(&pk_secret);
            self.pre_keys.push(PreKey {
                key_id: start_id + i,
                public_key: encode_b64(pk_public.as_bytes()),
                private_key: encode_b64(pk_secret.to_bytes().as_slice()),
            });
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SessionState {
    pub remote_identity_key: Option<String>,
    pub root_key: Option<String>, 
    pub send_chain_key: Option<String>, 
    pub recv_chain_key: Option<String>, 
    
    
    pub send_ratchet_key_private: Option<String>, 
    pub send_ratchet_key_public: Option<String>, 
    pub recv_ratchet_key: Option<String>, 
    
    
    pub sequence_number_send: u32,
    pub sequence_number_recv: u32, 
    pub prev_sequence_number_send: u32, 

    
    pub send_header_key: Option<String>,
    pub recv_header_key: Option<String>,
    pub next_send_header_key: Option<String>,
    pub next_recv_header_key: Option<String>,

    
    
    pub skipped_message_keys: HashMap<String, String>,

    
    pub is_verified: bool,
    pub verified_identity_key: Option<String>,
    pub verification_timestamp: Option<u64>,

    
    pub last_sent_hash: Option<String>,
    pub last_recv_hash: Option<String>,

    
    pub pq_ct1: Option<String>,
    pub pq_ct2: Option<String>,
    pub pq_shared_secret: Option<String>, 
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MediaKeyBundle {
    pub key: String, 
    pub nonce: String, 
    pub digest: String, 
    pub file_name: String,
    pub file_type: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SenderKey {
    pub key_id: u32,
    pub chain_key: String, 
    pub signature_key_private: String, 
    pub signature_key_public: String, 
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GroupState {
    pub group_id: String,
    pub my_sender_key: Option<SenderKey>,
    pub member_sender_keys: HashMap<String, SenderKey>, 
}

impl GroupState {
    pub fn save_to_db(&self, conn: &Connection) -> Result<(), String> {
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO groups (group_id, state) VALUES (?1, ?2);",
            params![self.group_id, json],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_from_db(conn: &Connection, group_id: &str) -> Result<Option<Self>, String> {
        let mut stmt = conn.prepare("SELECT state FROM groups WHERE group_id = ?1;").map_err(|e| e.to_string())?;
        let mut rows = stmt.query([group_id]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let json: String = row.get(0).map_err(|e| e.to_string())?;
            let state: GroupState = serde_json::from_str(&json).map_err(|e| e.to_string())?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PendingMessage {
    pub id: String,
    pub recipient_hash: String,
    pub body: String, 
    pub timestamp: u64,
    pub retries: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SealedEnvelope {
    pub sender: String, 
    pub message: serde_json::Value,
}

impl SessionState {
    pub fn save_to_db(&self, conn: &Connection, peer_hash: &str) -> Result<(), String> {
        let json = serde_json::to_string(self).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO vault (key, value) VALUES (?1, ?2);",
            params![format!("session_{}", peer_hash), json],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_from_db(conn: &Connection, peer_hash: &str) -> Result<Option<Self>, String> {
        let mut stmt = conn.prepare("SELECT value FROM vault WHERE key = ?1;").map_err(|e| e.to_string())?;
        let mut rows = stmt.query([format!("session_{}", peer_hash)]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let json: String = row.get(0).map_err(|e| e.to_string())?;
            let state: SessionState = serde_json::from_str(&json).map_err(|e| e.to_string())?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }
}



pub fn decode_b64(s: &str) -> Result<Vec<u8>, String> {
    BASE64.decode(s).map_err(|e| e.to_string())
}

pub fn encode_b64(b: &[u8]) -> String {
    BASE64.encode(b)
}

pub fn sign_message(conn: &Connection, message: &[u8]) -> Result<String, String> {
    let mut stmt = conn.prepare("SELECT value FROM vault WHERE key = 'protocol_identity';").map_err(|e| e.to_string())?;
    let json: String = stmt.query_row([], |r| r.get(0)).map_err(|e| e.to_string())?;
    let id: ProtocolIdentity = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    
    let sk_bytes = decode_b64(&id.identity_keys.private_key)?;
    let sk = SecretKey::from_bytes(&sk_bytes).map_err(|_| "Invalid private key bytes")?;
    let pk = PublicKey::from(&sk);
    let keypair = Keypair { secret: sk, public: pk };
    
    let signature = keypair.sign(message);
    Ok(encode_b64(&signature.to_bytes()))
}



fn kdf_rk(rk: &[u8], dh_out: &[u8]) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut okm = [0u8; 96]; 
    hk.expand(b"EntropyV1 Ratchet", &mut okm).map_err(|_| "HKDF Expand failed")?;
    
    let mut new_rk = [0u8; 32];
    let mut new_ck = [0u8; 32];
    let mut new_hk = [0u8; 32];
    new_rk.copy_from_slice(&okm[0..32]);
    new_ck.copy_from_slice(&okm[32..64]);
    new_hk.copy_from_slice(&okm[64..96]);
    
    Ok((new_rk, new_ck, new_hk))
}


fn rk_mix_pq(rk: &[u8], pq_secret: &[u8]) -> Result<[u8; 32], String> {
    let hk = Hkdf::<Sha256>::new(Some(rk), pq_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"EntropyV1 PQ Mix", &mut okm).map_err(|_| "PQ Mix failed")?;
    Ok(okm)
}

fn kdf_ck(ck: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ck).map_err(|e| e.to_string())?;
    mac.update(b"\x01");
    let new_ck_bytes = mac.finalize().into_bytes();
    
    let mut mac2 = <Hmac<Sha256> as Mac>::new_from_slice(ck).map_err(|e| e.to_string())?;
    mac2.update(b"\x02");
    let mk_bytes = mac2.finalize().into_bytes();

    let mut ck_res = [0u8; 32];
    let mut mk_res = [0u8; 32];
    ck_res.copy_from_slice(&new_ck_bytes);
    mk_res.copy_from_slice(&mk_bytes);

    Ok((ck_res, mk_res))
}

fn pad_message(message: &[u8]) -> Vec<u8> {
    
    
    let block_size = 512;
    let pad_len = block_size - (message.len() % block_size);
    let mut padded = Vec::with_capacity(message.len() + pad_len);
    padded.extend_from_slice(message);
    
    
    for _ in 0..pad_len {
        padded.push((pad_len % 256) as u8);
    }
    
    let len_bytes = (pad_len as u16).to_be_bytes();
    padded.push(len_bytes[0]);
    padded.push(len_bytes[1]);
    padded
}

fn unpad_message(padded: &[u8]) -> Result<Vec<u8>, String> {
    if padded.len() < 2 { return Err("Message too short".to_string()); }
    
    let last_two = &padded[padded.len()-2..];
    let pad_len = u16::from_be_bytes([last_two[0], last_two[1]]) as usize;
    
    if pad_len == 0 || pad_len > padded.len() {
        return Err("Invalid padding".to_string());
    }
    Ok(padded[..padded.len() - pad_len - 2].to_vec())
}



fn encrypt_header(key: &[u8], ratchet_pub: &[u8], n: u32, pn: u32) -> Result<(String, String), String> {
    let header_json = serde_json::json!({
        "ratchet_key": BASE64.encode(ratchet_pub),
        "n": n,
        "pn": pn
    }).to_string();

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let mut rng = thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, header_json.as_bytes()).map_err(|e| e.to_string())?;
    Ok((BASE64.encode(&ciphertext), BASE64.encode(&nonce_bytes)))
}

fn decrypt_header(key: &[u8], ciphertext: &str, nonce_b64: &str) -> Result<serde_json::Value, String> {
    let ciphertext_bytes = BASE64.decode(ciphertext).map_err(|e| e.to_string())?;
    let nonce_bytes = BASE64.decode(nonce_b64).map_err(|e| e.to_string())?;
    
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let plaintext = cipher.decrypt(nonce, ciphertext_bytes.as_slice()).map_err(|e| e.to_string())?;
    serde_json::from_slice(&plaintext).map_err(|e| e.to_string())
}


pub fn ed25519_pub_to_x25519(ed_pub: &[u8]) -> Result<[u8; 32], String> {
    if ed_pub.len() != 32 { return Err("Invalid Ed25519 key length".to_string()); }
    
    
    let compressed = CompressedEdwardsY::from_slice(ed_pub);
    let ed_point = compressed.decompress().ok_or("Invalid Ed25519 public key (decompression failed)")?;
    let x25519_pub = ed_point.to_montgomery();
    
    Ok(x25519_pub.to_bytes())
}


fn ed25519_priv_to_x25519(ed_priv_seed: &[u8]) -> Result<StaticSecret, String> {
    if ed_priv_seed.len() != 32 { return Err("Invalid Ed25519 seed length".to_string()); }
    let mut hasher = Sha512::new();
    hasher.update(ed_priv_seed);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[0..32]);
    Ok(StaticSecret::from(bytes))
}



pub fn calculate_safety_number(me_ik: &str, peer_ik: &str) -> Result<String, String> {
    let mut keys = vec![me_ik.to_string(), peer_ik.to_string()];
    keys.sort();
    
    let mut hasher = Sha256::new();
    hasher.update(b"EntropySafetyNumberV1");
    hasher.update(keys[0].as_bytes());
    hasher.update(keys[1].as_bytes());
    
    let hash = hasher.finalize();
    
    let mut result = String::new();
    for chunk in hash.chunks(4) {
        let val = u32::from_be_bytes(<[u8; 4]>::try_from(chunk).unwrap_or([0; 4]));
        result.push_str(&format!("{:05} ", val % 100000));
        if result.len() >= 35 { break; } 
    }
    
    Ok(result.trim().to_string())
}

pub fn generate_new_identity() -> ProtocolIdentity {
    let mut rng = thread_rng();
    
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let id_secret = SecretKey::from_bytes(&sk_bytes).unwrap();
    let id_public = PublicKey::from(&id_secret);
    let id_keypair = Keypair { secret: id_secret, public: id_public };

    
    let (pq_id_pk, pq_id_sk) = kyber1024::keypair();

    let mut spk_bytes = [0u8; 32];
    rng.fill_bytes(&mut spk_bytes);
    let spk_secret = StaticSecret::from(spk_bytes);
    let spk_public = X25519PublicKey::from(&spk_secret);
    let signature = id_keypair.sign(spk_public.as_bytes());

    
    let (pq_spk_pk, pq_spk_sk) = kyber1024::keypair();

    let mut pre_keys = Vec::new();
    for i in 0..10 {
        let mut pk_bytes = [0u8; 32];
        rng.fill_bytes(&mut pk_bytes);
        let pk_secret = StaticSecret::from(pk_bytes);
        let pk_public = X25519PublicKey::from(&pk_secret);
        pre_keys.push(PreKey {
            key_id: i + 1,
            public_key: encode_b64(pk_public.as_bytes()),
            private_key: encode_b64(pk_secret.to_bytes().as_ref()),
        });
    }

    ProtocolIdentity {
        registration_id: (rng.next_u32() % 16383) + 1,
        identity_keys: IdentityKeys {
            public_key: encode_b64(id_keypair.public.as_bytes()),
            private_key: encode_b64(id_keypair.secret.as_bytes()),
            pq_public_key: encode_b64(pq_id_pk.as_bytes()),
            pq_private_key: encode_b64(pq_id_sk.as_bytes()),
        },
        signed_pre_key: SignedPreKey {
            key_id: 1,
            public_key: encode_b64(spk_public.as_bytes()),
            private_key: encode_b64(spk_secret.to_bytes().as_ref()),
            signature: encode_b64(&signature.to_bytes()),
            pq_public_key: encode_b64(pq_spk_pk.as_bytes()),
            pq_private_key: encode_b64(pq_spk_sk.as_bytes()),
        },
        pre_keys,
    }
}

pub fn establish_outbound_session(
    conn: &Connection,
    remote_hash: &str,
    bundle: &serde_json::Value
) -> Result<(), String> {
    let identity = ProtocolIdentity::load_from_db(conn)?.ok_or("No identity")?;
    
    
    let my_id_priv_bytes = decode_b64(&identity.identity_keys.private_key)?;
    let my_id_secret = ed25519_priv_to_x25519(&my_id_priv_bytes)?;

    let mut rng = thread_rng();
    let mut my_ephemeral_bytes = [0u8; 32];
    rng.fill_bytes(&mut my_ephemeral_bytes);
    let my_ephemeral_secret = StaticSecret::from(my_ephemeral_bytes);
    let my_ephemeral_public = X25519PublicKey::from(&my_ephemeral_secret);

    let remote_id_key_bytes = decode_b64(bundle["identityKey"].as_str().unwrap_or_default())?;
    let remote_spk_bytes = decode_b64(bundle["signedPreKey"]["publicKey"].as_str().unwrap_or_default())?;
    let remote_opk_bytes = if let Some(pk) = bundle["preKeys"].as_array().and_then(|a| a.first()) {
        Some(decode_b64(pk["publicKey"].as_str().unwrap_or_default())?)
    } else {
        None
    };

    let remote_id_public_bytes = ed25519_pub_to_x25519(&remote_id_key_bytes)?;
    let remote_id_public = X25519PublicKey::from(remote_id_public_bytes);
    let remote_spk_public = X25519PublicKey::from(<[u8; 32]>::try_from(remote_spk_bytes.as_slice()).map_err(|_| "Invalid Remote SPK")?);

    
    let dh1 = my_id_secret.diffie_hellman(&remote_spk_public);
    let dh2 = my_ephemeral_secret.diffie_hellman(&remote_id_public);
    let dh3 = my_ephemeral_secret.diffie_hellman(&remote_spk_public);
    
    let mut km = Vec::new();
    km.extend_from_slice(dh1.as_bytes());
    km.extend_from_slice(dh2.as_bytes());
    km.extend_from_slice(dh3.as_bytes());

    if let Some(opk_bytes) = remote_opk_bytes {
        let remote_opk_public = X25519PublicKey::from(<[u8; 32]>::try_from(opk_bytes.as_slice()).map_err(|_| "Invalid Remote OPK")?);
        let dh4 = my_ephemeral_secret.diffie_hellman(&remote_opk_public);
        km.extend_from_slice(dh4.as_bytes());
    }

    
    let remote_pq_id_pk = kyber1024::PublicKey::from_bytes(&decode_b64(bundle["pq_identityKey"].as_str().unwrap_or_default())?).map_err(|_| "Invalid PQ IK")?;
    let remote_pq_spk = kyber1024::PublicKey::from_bytes(&decode_b64(bundle["signedPreKey"]["pq_publicKey"].as_str().unwrap_or_default())?).map_err(|_| "Invalid PQ SPK")?;
    
    let (pq_ss1, pq_ct1) = kyber1024::encapsulate(&remote_pq_id_pk);
    let (pq_ss2, pq_ct2) = kyber1024::encapsulate(&remote_pq_spk);
    
    km.extend_from_slice(pq_ss1.as_bytes());
    km.extend_from_slice(pq_ss2.as_bytes());

    let hk = Hkdf::<Sha256>::new(None, &km);
    let mut root_key_bytes = [0u8; 32];
    hk.expand(b"EntropyV1 X3DH+PQ", &mut root_key_bytes).map_err(|e| e.to_string())?;

    let hk_gen = Hkdf::<Sha256>::new(None, &root_key_bytes);
    let mut hk_send = [0u8; 32];
    let mut hk_recv = [0u8; 32];
    hk_gen.expand(b"EntropyV1 HeaderSend", &mut hk_send).map_err(|e| e.to_string())?;
    hk_gen.expand(b"EntropyV1 HeaderRecv", &mut hk_recv).map_err(|e| e.to_string())?;

    let (rk_1, ck_1, _hk_ignored) = kdf_rk(&root_key_bytes, dh3.as_bytes())?;

    let state = SessionState {
        remote_identity_key: Some(encode_b64(remote_id_key_bytes.as_slice())),
        root_key: Some(encode_b64(&rk_1)),
        send_chain_key: Some(encode_b64(&ck_1)), 
        recv_chain_key: None, 
        send_ratchet_key_private: Some(encode_b64(my_ephemeral_secret.to_bytes().as_slice())),
        send_ratchet_key_public: Some(encode_b64(my_ephemeral_public.as_bytes())),
        recv_ratchet_key: Some(encode_b64(remote_spk_public.as_bytes())), 
        sequence_number_send: 0,
        sequence_number_recv: 0,
        prev_sequence_number_send: 0,
        send_header_key: Some(encode_b64(&hk_send)),
        recv_header_key: Some(encode_b64(&hk_recv)),
        next_send_header_key: None,
        next_recv_header_key: None,
        skipped_message_keys: HashMap::new(),
        is_verified: false,
        verified_identity_key: Some(encode_b64(remote_id_key_bytes.as_slice())),
        verification_timestamp: None,
        last_sent_hash: None,
        last_recv_hash: None,
        pq_ct1: Some(encode_b64(pq_ct1.as_bytes())),
        pq_ct2: Some(encode_b64(pq_ct2.as_bytes())),
        pq_shared_secret: {
            let mut combined = pq_ss1.as_bytes().to_vec();
            combined.extend_from_slice(pq_ss2.as_bytes());
            Some(encode_b64(&combined))
        },
    };

    state.save_to_db(conn, remote_hash)?;
    Ok(())
}

fn skip_message_keys(state: &mut SessionState, target_n: u32) -> Result<(), String> {
    if state.sequence_number_recv >= target_n { return Ok(()); }
    if target_n - state.sequence_number_recv > 100 {
        return Err("Too many messages to skip".to_string());
    }
    
    let ratchet_pub = state.recv_ratchet_key.clone().ok_or("No ratchet key")?;
    let mut current_ck = decode_b64(state.recv_chain_key.as_ref().ok_or("No recv chain")?)?;
    
    while state.sequence_number_recv < target_n {
        let (next_ck, mk) = kdf_ck(&current_ck)?;
        let key = format!("{}_{}", ratchet_pub, state.sequence_number_recv);
        state.skipped_message_keys.insert(key, encode_b64(&mk));
        current_ck = next_ck.to_vec();
        state.sequence_number_recv += 1;
    }
    
    state.recv_chain_key = Some(encode_b64(&current_ck));
    Ok(())
}

pub fn ratchet_encrypt(
    conn: &Connection,
    remote_hash: &str,
    plaintext: &str
) -> Result<serde_json::Value, String> {
    let mut state = SessionState::load_from_db(conn, remote_hash)?.ok_or("No session available")?;
    
    
    if state.send_chain_key.is_none() {
        let root_key = decode_b64(state.root_key.as_ref().ok_or("No root key")?)?;
        let remote_ratchet_bytes = decode_b64(state.recv_ratchet_key.as_ref().ok_or("No remote ratchet key")?)?;
        let remote_ratchet = X25519PublicKey::from(<[u8; 32]>::try_from(remote_ratchet_bytes).map_err(|_| "Invalid key size")?);

        let mut rng = thread_rng();
        let mut my_priv_bytes = [0u8; 32];
        rng.fill_bytes(&mut my_priv_bytes);
        let my_priv = StaticSecret::from(my_priv_bytes);
        let my_pub = X25519PublicKey::from(&my_priv);

        let dh = my_priv.diffie_hellman(&remote_ratchet);
        let (mut new_rk, ck, _hk_ignored) = kdf_rk(&root_key, dh.as_bytes())?;

        
        if let Some(pq_ss_b64) = &state.pq_shared_secret {
            if let Ok(pq_ss) = decode_b64(pq_ss_b64) {
                new_rk = rk_mix_pq(&new_rk, &pq_ss)?;
            }
        }
        
        
        let curr_hk = decode_b64(state.send_header_key.as_ref().ok_or("No header key")?)?;
        let mut hasher = Sha256::new();
        hasher.update(&curr_hk);
        let next_hk = hasher.finalize();

        state.root_key = Some(encode_b64(&new_rk));
        state.send_chain_key = Some(encode_b64(&ck));
        state.send_header_key = Some(encode_b64(&next_hk));
        state.send_ratchet_key_private = Some(encode_b64(my_priv.to_bytes().as_slice()));
        state.send_ratchet_key_public = Some(encode_b64(my_pub.as_bytes()));
    }

    let current_ck_b64 = state.send_chain_key.clone().ok_or("No send chain key")?;
    let current_ck = decode_b64(&current_ck_b64)?;
    let (new_ck, mk) = kdf_ck(&current_ck)?;
    
    
    let padded_pt = pad_message(plaintext.as_bytes());

    let cipher = Aes256Gcm::new_from_slice(&mk).map_err(|e| e.to_string())?;
    let mut rng = thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, padded_pt.as_slice()).map_err(|e| e.to_string())?;
    
    
    let mut hasher = Sha256::new();
    hasher.update(&ciphertext);
    state.last_sent_hash = Some(hex::encode(hasher.finalize()));

    
    
    let lock_hash = state.last_recv_hash.clone().unwrap_or_default();

    state.send_chain_key = Some(encode_b64(&new_ck));
    let n = state.sequence_number_send;
    state.sequence_number_send += 1;
    state.save_to_db(conn, remote_hash)?;

    let ratchet_pub_bytes = decode_b64(&state.send_ratchet_key_public.clone().unwrap_or_default())?;
    let header_key_bytes = decode_b64(&state.send_header_key.clone().ok_or("No header key")?)?;

    let (header_enc, header_nonce) = encrypt_header(
        &header_key_bytes, 
        &ratchet_pub_bytes, 
        n, 
        state.prev_sequence_number_send
    )?;

    let mut msg_payload = serde_json::json!({
        "type": if n == 0 { 3 } else { 1 },
        "body": encode_b64(&ciphertext),
        "nonce": encode_b64(&nonce_bytes), 
        "header_enc": header_enc,
        "header_nonce": header_nonce,
        "lh": lock_hash 
    });

    if let Some(pq1) = state.pq_ct1.take() {
        msg_payload["pq1"] = serde_json::Value::String(pq1);
    }
    if let Some(pq2) = state.pq_ct2.take() {
        msg_payload["pq2"] = serde_json::Value::String(pq2);
    }

    
    
    if n == 0 {
        if let Ok(Some(me)) = ProtocolIdentity::load_from_db(conn) {
            msg_payload["ik"] = serde_json::Value::String(me.identity_keys.public_key);
            msg_payload["pq_ik"] = serde_json::Value::String(me.identity_keys.pq_public_key);
        }
    }
    msg_payload["ek"] = serde_json::Value::String(state.send_ratchet_key_public.clone().unwrap_or_default());

    state.save_to_db(conn, remote_hash)?;
    Ok(msg_payload)
}


#[allow(dead_code)]
pub fn attach_pq_handshake(mut msg: serde_json::Value, pq_ct1: String, pq_ct2: String) -> serde_json::Value {
    msg["pq_ct1"] = serde_json::Value::String(pq_ct1);
    msg["pq_ct2"] = serde_json::Value::String(pq_ct2);
    msg
}

pub fn ratchet_decrypt(
    conn: &Connection,
    remote_hash: &str,
    msg_obj: &serde_json::Value
) -> Result<String, String> {
    let mut state_opt = SessionState::load_from_db(conn, remote_hash)?;

    
    if state_opt.is_none() {
        let alice_ik_b64 = msg_obj.get("ik").and_then(|v| v.as_str()).ok_or("Missing IK in PreKey")?;
        let alice_ek_b64 = msg_obj.get("ek").and_then(|v| v.as_str()).ok_or("Missing EK in PreKey")?;

        let alice_ik_bytes = decode_b64(alice_ik_b64)?;
        let alice_ek_bytes = decode_b64(alice_ek_b64)?;
        
        let alice_ik = X25519PublicKey::from(ed25519_pub_to_x25519(&alice_ik_bytes)?);
        let alice_ek = X25519PublicKey::from(<[u8; 32]>::try_from(alice_ek_bytes).map_err(|_| "Invalid EK size")?);

        let identity = ProtocolIdentity::load_from_db(conn)?.ok_or("No identity")?;
        let bob_ik_priv = decode_b64(&identity.identity_keys.private_key)?;
        let bob_ik = ed25519_priv_to_x25519(&bob_ik_priv)?;
        let bob_spk_priv = decode_b64(&identity.signed_pre_key.private_key)?;
        let bob_spk = StaticSecret::from(<[u8; 32]>::try_from(bob_spk_priv).map_err(|_| "Invalid SPK size")?);

        let dh1 = bob_spk.diffie_hellman(&alice_ik);
        let dh2 = bob_ik.diffie_hellman(&alice_ek);
        let dh3 = bob_spk.diffie_hellman(&alice_ek);
        
        let mut km = Vec::new();
        km.extend_from_slice(dh1.as_bytes());
        km.extend_from_slice(dh2.as_bytes());
        km.extend_from_slice(dh3.as_bytes());

        
        let pq_ct1_b64 = msg_obj.get("pq1").and_then(|v| v.as_str()).ok_or("Missing PQ CT1")?;
        let pq_ct2_b64 = msg_obj.get("pq2").and_then(|v| v.as_str()).ok_or("Missing PQ CT2")?;
        
        let pq_ct1 = kyber1024::Ciphertext::from_bytes(&decode_b64(pq_ct1_b64)?).map_err(|_| "Invalid PQ CT1")?;
        let pq_ct2 = kyber1024::Ciphertext::from_bytes(&decode_b64(pq_ct2_b64)?).map_err(|_| "Invalid PQ CT2")?;
        
        let pq_id_sk = kyber1024::SecretKey::from_bytes(&decode_b64(&identity.identity_keys.pq_private_key)?).map_err(|_| "Invalid PQ ID SK")?;
        let pq_spk_sk = kyber1024::SecretKey::from_bytes(&decode_b64(&identity.signed_pre_key.pq_private_key)?).map_err(|_| "Invalid PQ SPK SK")?;
        
        let ss1 = kyber1024::decapsulate(&pq_ct1, &pq_id_sk);
        let ss2 = kyber1024::decapsulate(&pq_ct2, &pq_spk_sk);
        
        km.extend_from_slice(ss1.as_bytes());
        km.extend_from_slice(ss2.as_bytes());
        
        let hk_x3dh = Hkdf::<Sha256>::new(None, &km);
        let mut root_key_bytes = [0u8; 32];
        hk_x3dh.expand(b"EntropyV1 X3DH+PQ", &mut root_key_bytes).map_err(|e| e.to_string())?;

        let hk_gen = Hkdf::<Sha256>::new(None, &root_key_bytes);
        let mut hk_send = [0u8; 32];
        let mut hk_recv = [0u8; 32];
        
        hk_gen.expand(b"EntropyV1 HeaderSend", &mut hk_recv).map_err(|e| e.to_string())?;
        hk_gen.expand(b"EntropyV1 HeaderRecv", &mut hk_send).map_err(|e| e.to_string())?;

        let (rk_1, ck_1, _hk_ignored) = kdf_rk(&root_key_bytes, dh3.as_bytes())?;
        let new_state = SessionState {
            remote_identity_key: Some(alice_ik_b64.to_string()),
            root_key: Some(encode_b64(&rk_1)),
            send_chain_key: None, 
            recv_chain_key: Some(encode_b64(&ck_1)), 
            send_ratchet_key_private: Some(encode_b64(bob_spk.to_bytes().as_slice())),
            send_ratchet_key_public: Some(identity.signed_pre_key.public_key.clone()),
            recv_ratchet_key: Some(alice_ek_b64.to_string()), 
            sequence_number_send: 0,
            sequence_number_recv: 0,
            prev_sequence_number_send: 0,
            send_header_key: Some(encode_b64(&hk_send)), 
            recv_header_key: Some(encode_b64(&hk_recv)),
            next_send_header_key: None,
            next_recv_header_key: None,
            skipped_message_keys: HashMap::new(),
            is_verified: false,
            verified_identity_key: Some(alice_ik_b64.to_string()),
            verification_timestamp: None,
            last_sent_hash: None,
            last_recv_hash: None,
            pq_ct1: msg_obj.get("pq1").and_then(|v| v.as_str()).map(|s| s.to_string()),
            pq_ct2: msg_obj.get("pq2").and_then(|v| v.as_str()).map(|s| s.to_string()),
            pq_shared_secret: {
                let mut combined = ss1.as_bytes().to_vec();
                combined.extend_from_slice(ss2.as_bytes());
                Some(encode_b64(&combined))
            },
        };
        new_state.save_to_db(conn, remote_hash)?;
        state_opt = Some(new_state);
    }

    let mut state = state_opt.unwrap();
    let header_enc = msg_obj["header_enc"].as_str().ok_or("Missing header_enc")?;
    let header_nonce = msg_obj["header_nonce"].as_str().ok_or("Missing header_nonce")?;

    
    let recv_hk = decode_b64(&state.recv_header_key.clone().ok_or("No recv header key")?)?;
    let header = decrypt_header(&recv_hk, header_enc, header_nonce)
        .or_else(|_| {
            
            let mut h = Sha256::new();
            h.update(&recv_hk);
            let evolved_hk = h.finalize();
            decrypt_header(&evolved_hk, header_enc, header_nonce)
        })
        .or_else(|_| {
            
            if let Some(next_hk) = &state.next_recv_header_key {
                decrypt_header(&decode_b64(next_hk)?, header_enc, header_nonce)
            } else {
                Err("Header decryption failed".to_string())
            }
        })?;

    let remote_ratchet_b64 = header["ratchet_key"].as_str().ok_or("Missing ratchet_key in header")?;
    let n = header["n"].as_u64().ok_or("Missing n in header")? as u32;

    
    
    
    if let Some(claimed_prev_hash) = msg_obj.get("lh").and_then(|v| v.as_str()) {
        if !claimed_prev_hash.is_empty() {
             if let Some(expected_hash) = &state.last_sent_hash {
                 if claimed_prev_hash != expected_hash {
                     return Err("CONTINUITY_BREAK: Cryptographic sequence desync. Potential ghost device or message drop detected.".to_string());
                 }
             }
        }
    }

    
    
    if let Some(msg_ik) = msg_obj.get("ik").and_then(|v| v.as_str()) {
        if let Some(verified_ik) = &state.verified_identity_key {
            if msg_ik != verified_ik {
                 return Err("IDENTITY_CHANGED: The sender's identity has changed! Potential MITM attack.".to_string());
            }
        }
    }

    
    let key = format!("{}_{}", remote_ratchet_b64, n);
    if let Some(mk_b64) = state.skipped_message_keys.remove(&key) {
        let mk = decode_b64(&mk_b64)?;
        let body_b64 = msg_obj["body"].as_str().ok_or("No body")?;
        let nonce_b64 = msg_obj["nonce"].as_str().ok_or("No nonce")?;
        let cipher = Aes256Gcm::new_from_slice(&mk).map_err(|e| e.to_string())?;
        let nonce_vec = decode_b64(nonce_b64)?;
        let nonce = Nonce::from_slice(&nonce_vec);
        let body_vec = decode_b64(body_b64)?;
        let pt = cipher.decrypt(nonce, body_vec.as_slice()).map_err(|e| e.to_string())?;
        
        let unpadded_pt = unpad_message(&pt)?;
        state.save_to_db(conn, remote_hash)?;
        return Ok(String::from_utf8(unpadded_pt).map_err(|e| e.to_string())?);
    }

    if remote_ratchet_b64 != state.recv_ratchet_key.as_ref().unwrap_or(&"".to_string()) {
        
        skip_message_keys(&mut state, header["pn"].as_u64().unwrap_or(0) as u32)?;
        
        let priv_ratchet_bytes = decode_b64(state.send_ratchet_key_private.as_ref().ok_or("No send ratchet private")?)?;
        let priv_ratchet = StaticSecret::from(<[u8; 32]>::try_from(priv_ratchet_bytes).map_err(|_| "Invalid ratchet key size")?);
        let pub_ratchet = X25519PublicKey::from(<[u8; 32]>::try_from(decode_b64(remote_ratchet_b64)?).map_err(|_| "Invalid remote ratchet key")?);
        let root_key = decode_b64(state.root_key.as_ref().ok_or("No root key")?)?;

        
        let dh_recv = priv_ratchet.diffie_hellman(&pub_ratchet);
        let (mut rk_next, ck_recv, _hk_ignored) = kdf_rk(&root_key, dh_recv.as_bytes())?;
        
        
        if let Some(pq_ss_b64) = &state.pq_shared_secret {
            if let Ok(pq_ss) = decode_b64(pq_ss_b64) {
                rk_next = rk_mix_pq(&rk_next, &pq_ss)?;
            }
        }

        
        let mut rng = thread_rng();
        let mut next_priv_bytes = [0u8; 32];
        rng.fill_bytes(&mut next_priv_bytes);
        let next_priv = StaticSecret::from(next_priv_bytes);
        let next_pub = X25519PublicKey::from(&next_priv);
        let dh_send = next_priv.diffie_hellman(&pub_ratchet);
        let (mut rk_final, ck_send, _hk_ignored) = kdf_rk(&rk_next, dh_send.as_bytes())?;

        
        if let Some(pq_ss_b64) = &state.pq_shared_secret {
            if let Ok(pq_ss) = decode_b64(pq_ss_b64) {
                rk_final = rk_mix_pq(&rk_final, &pq_ss)?;
            }
        }
        
        
        let curr_recv_hk = decode_b64(state.recv_header_key.as_ref().unwrap())?;
        let curr_send_hk = decode_b64(state.send_header_key.as_ref().unwrap())?;
        
        let mut h1 = Sha256::new(); h1.update(&curr_recv_hk);
        let next_recv_hk = h1.finalize();
        
        let mut h2 = Sha256::new(); h2.update(&curr_send_hk);
        let next_send_hk = h2.finalize();

        state.root_key = Some(encode_b64(&rk_final));
        state.recv_chain_key = Some(encode_b64(&ck_recv));
        state.send_chain_key = Some(encode_b64(&ck_send));
        state.send_ratchet_key_private = Some(encode_b64(next_priv.to_bytes().as_slice()));
        state.send_ratchet_key_public = Some(encode_b64(next_pub.as_bytes()));
        state.recv_ratchet_key = Some(remote_ratchet_b64.to_string());
        state.recv_header_key = Some(encode_b64(&next_recv_hk));
        state.send_header_key = Some(encode_b64(&next_send_hk));
        state.prev_sequence_number_send = state.sequence_number_send;
        state.sequence_number_send = 0;
        state.sequence_number_recv = 0;
    }

    skip_message_keys(&mut state, n)?;
    let cur_ck = decode_b64(state.recv_chain_key.as_ref().ok_or("No recv chain")?)?;
    let (next_ck, mk) = kdf_ck(&cur_ck)?;
    state.recv_chain_key = Some(encode_b64(&next_ck));
    state.sequence_number_recv += 1;
    
    
    if state.skipped_message_keys.len() > 1000 {
        let keys_to_remove: Vec<String> = state.skipped_message_keys.keys()
            .take(state.skipped_message_keys.len() - 1000)
            .cloned().collect();
        for k in keys_to_remove { state.skipped_message_keys.remove(&k); }
    }

    let cipher = Aes256Gcm::new_from_slice(&mk).map_err(|e| e.to_string())?;
    let nonce_vec = decode_b64(msg_obj["nonce"].as_str().ok_or("No nonce")?)?;
    let nonce = Nonce::from_slice(&nonce_vec);
    let body_vec = decode_b64(msg_obj["body"].as_str().ok_or("No body")?)?;
    let pt = cipher.decrypt(nonce, body_vec.as_slice()).map_err(|e| e.to_string())?;
    
    let unpadded_pt = unpad_message(&pt)?;

    
    let mut hasher = Sha256::new();
    hasher.update(body_vec.as_slice());
    state.last_recv_hash = Some(hex::encode(hasher.finalize()));

    state.save_to_db(conn, remote_hash)?;
    Ok(String::from_utf8(unpadded_pt).map_err(|e| e.to_string())?)
}



pub fn seal_sender(
    message_body: serde_json::Value,
    sender_identity_b64: &str,
    recipient_public_key: &X25519PublicKey,
    recipient_pq_public_key_b64: &str
) -> Result<serde_json::Value, String> {
    let mut rng = thread_rng();
    
    
    let mut ephemeral_bytes = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_bytes);
    let ephemeral_secret = StaticSecret::from(ephemeral_bytes);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(recipient_public_key);

    
    let recipient_pq_pk = kyber1024::PublicKey::from_bytes(&decode_b64(recipient_pq_public_key_b64)?).map_err(|_| "Invalid PQ PK")?;
    let (pq_ss, pq_ct) = kyber1024::encapsulate(&recipient_pq_pk);

    
    let mut km = Vec::new();
    km.extend_from_slice(shared_secret.as_bytes());
    km.extend_from_slice(pq_ss.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&km);
    let aes_key = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let envelope = SealedEnvelope {
        sender: sender_identity_b64.to_string(),
        message: message_body,
    };
    let envelope_content = serde_json::to_string(&envelope).map_err(|e| e.to_string())?;

    let ciphertext = cipher.encrypt(nonce, envelope_content.as_bytes()).map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "sealed": true,
        "ephemeral_public": encode_b64(ephemeral_public.as_bytes()),
        "pq_ct": encode_b64(pq_ct.as_bytes()),
        "nonce": encode_b64(&nonce_bytes),
        "ciphertext": encode_b64(&ciphertext)
    }))
}

pub fn unseal_sender(
    sealed_obj: &serde_json::Value,
    my_identity_secret: &StaticSecret,
    my_pq_identity_secret: &kyber1024::SecretKey
) -> Result<(String, serde_json::Value), String> {
    let ephem_b64 = sealed_obj["ephemeral_public"].as_str().ok_or("No ephemeral_public")?;
    let pq_ct_b64 = sealed_obj["pq_ct"].as_str().ok_or("No pq_ct")?;
    let nonce_b64 = sealed_obj["nonce"].as_str().ok_or("No nonce")?;
    let ct_b64 = sealed_obj["ciphertext"].as_str().ok_or("No ciphertext")?;

    
    let ephem_bytes = decode_b64(ephem_b64)?;
    let mut ephem_arr = [0u8; 32];
    ephem_arr.copy_from_slice(&ephem_bytes);
    let ephem_pub = X25519PublicKey::from(ephem_arr);
    let shared_secret = my_identity_secret.diffie_hellman(&ephem_pub);

    
    let pq_ct = kyber1024::Ciphertext::from_bytes(&decode_b64(pq_ct_b64)?).map_err(|_| "Invalid PQ CT")?;
    let pq_ss = kyber1024::decapsulate(&pq_ct, my_pq_identity_secret);

    
    let mut km = Vec::new();
    km.extend_from_slice(shared_secret.as_bytes());
    km.extend_from_slice(pq_ss.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&km);
    let aes_key = hasher.finalize();

    let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| e.to_string())?;
    let nonce_vec = decode_b64(nonce_b64).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_vec);
    let ct_vec = decode_b64(ct_b64).map_err(|e| e.to_string())?;

    let pt = cipher.decrypt(nonce, ct_vec.as_slice()).map_err(|e| e.to_string())?;
    let envelope: SealedEnvelope = serde_json::from_slice(&pt).map_err(|e| e.to_string())?;

    let sender = envelope.sender;
    let message = envelope.message;

    Ok((sender, message))
}





pub fn create_group_sender_key() -> SenderKey {
    let mut rng = thread_rng();
    let mut ck = [0u8; 32];
    rng.fill_bytes(&mut ck);
    
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let id_secret = SecretKey::from_bytes(&sk_bytes).map_err(|_| "Invalid key size").unwrap_or_else(|_| SecretKey::from_bytes(&[0u8; 32]).unwrap()); 
    
    
    let id_public = PublicKey::from(&id_secret);

    SenderKey {
        key_id: rng.next_u32(),
        chain_key: encode_b64(&ck),
        signature_key_private: encode_b64(id_secret.as_bytes()),
        signature_key_public: encode_b64(id_public.as_bytes()),
    }
}

pub fn group_encrypt(
    _conn: &Connection,
    state: &mut GroupState,
    plaintext: &str
) -> Result<serde_json::Value, String> {
    let sk = state.my_sender_key.as_mut().ok_or("No group sender key")?;
    let cur_ck = decode_b64(&sk.chain_key)?;
    let (next_ck, mk) = kdf_ck(&cur_ck)?;
    sk.chain_key = encode_b64(&next_ck);

    let cipher = Aes256Gcm::new_from_slice(&mk).map_err(|e| e.to_string())?;
    let mut rng = thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    
    let padded = pad_message(plaintext.as_bytes());
    let ciphertext = cipher.encrypt(nonce, padded.as_slice()).map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "body": encode_b64(&ciphertext),
        "nonce": encode_b64(&nonce_bytes),
        "key_id": sk.key_id
    }))
}

pub fn create_group_distribution_message(
    state: &GroupState
) -> Result<serde_json::Value, String> {
    let sk = state.my_sender_key.as_ref().ok_or("No group sender key")?;
    Ok(serde_json::json!({
        "type": "group_sender_key_distribution",
        "group_id": state.group_id,
        "key_id": sk.key_id,
        "chain_key": sk.chain_key,
        "signature_key_public": sk.signature_key_public
    }))
}

pub fn verify_session(
    conn: &Connection,
    remote_hash: &str,
    is_verified: bool
) -> Result<(), String> {
    let mut state = SessionState::load_from_db(conn, remote_hash)?.ok_or("Session not found")?;
    state.is_verified = is_verified;
    state.verification_timestamp = if is_verified { 
        Some(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)) 
    } else { None };
    state.save_to_db(conn, remote_hash)?;
    Ok(())
}

pub fn group_decrypt(
    state: &mut GroupState,
    sender_hash: &str,
    msg_obj: &serde_json::Value
) -> Result<String, String> {
    let sk = state.member_sender_keys.get_mut(sender_hash).ok_or("No sender key for peer in group")?;
    let body_b64 = msg_obj["body"].as_str().ok_or("No body")?;
    let nonce_b64 = msg_obj["nonce"].as_str().ok_or("No nonce")?;
    
    let cur_ck = decode_b64(&sk.chain_key)?;
    let (next_ck, mk) = kdf_ck(&cur_ck)?;
    sk.chain_key = encode_b64(&next_ck);

    let cipher = Aes256Gcm::new_from_slice(&mk).map_err(|e| e.to_string())?;
    let nonce_vec = decode_b64(nonce_b64)?;
    let nonce = Nonce::from_slice(&nonce_vec);
    let body_vec = decode_b64(body_b64)?;
    
    let pt = cipher.decrypt(nonce, body_vec.as_slice()).map_err(|e| e.to_string())?;
    let unpadded = unpad_message(&pt)?;
    
    Ok(String::from_utf8(unpadded).map_err(|e| e.to_string())?)
}



pub fn encrypt_media(
    _conn: &Connection,
    plaintext: &[u8],
    file_name: &str,
    file_type: &str
) -> Result<(Vec<u8>, MediaKeyBundle), String> {
    let mut rng = thread_rng();
    let mut key_bytes = [0u8; 32];
    rng.fill_bytes(&mut key_bytes);
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())?;

    let mut hasher = Sha256::new();
    hasher.update(plaintext);
    let digest = hasher.finalize();

    let bundle = MediaKeyBundle {
        key: encode_b64(&key_bytes),
        nonce: encode_b64(&nonce_bytes),
        digest: encode_b64(&digest),
        file_name: file_name.to_string(),
        file_type: file_type.to_string(),
    };

    Ok((ciphertext, bundle))
}

pub fn decrypt_media(
    _conn: &Connection,
    ciphertext: &[u8],
    bundle: &MediaKeyBundle
) -> Result<Vec<u8>, String> {
    let key_bytes = decode_b64(&bundle.key)?;
    let nonce_bytes = decode_b64(&bundle.nonce)?;
    
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;
    
    let mut hasher = Sha256::new();
    hasher.update(&pt);
    let digest = hasher.finalize();

    if encode_b64(&digest) != bundle.digest {
        return Err("Media digest mismatch".to_string());
    }

    Ok(pt)
}



pub fn save_pending_message(conn: &Connection, msg: &PendingMessage) -> Result<(), String> {
    conn.execute(
        "INSERT OR REPLACE INTO pending_messages (id, recipient_hash, body, timestamp, retries) VALUES (?1, ?2, ?3, ?4, ?5);",
        params![msg.id, msg.recipient_hash, msg.body, msg.timestamp, msg.retries],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn get_pending_messages(conn: &Connection) -> Result<Vec<PendingMessage>, String> {
    let mut stmt = conn.prepare("SELECT id, recipient_hash, body, timestamp, retries FROM pending_messages;").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        Ok(PendingMessage {
            id: row.get(0)?,
            recipient_hash: row.get(1)?,
            body: row.get(2)?,
            timestamp: row.get(3)?,
            retries: row.get(4)?,
        })
    }).map_err(|e| e.to_string())?;

    let mut msgs = Vec::new();
    for row in rows {
        msgs.push(row.map_err(|e| e.to_string())?);
    }
    Ok(msgs)
}

pub fn remove_pending_message(conn: &Connection, id: &str) -> Result<(), String> {
    conn.execute("DELETE FROM pending_messages WHERE id = ?1;", [id]).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn mine_pow(seed: &str, difficulty: u32, context: &str) -> Result<(u64, String), String> {
    let mut nonce: u64 = 0;
    let target = "0".repeat(difficulty as usize);
    let prefix = format!("{}{}", seed, context);
    let prefix_bytes = prefix.as_bytes();
    
    if difficulty > 9 {
        return Err(format!("PoW difficulty {} is dangerously high.", difficulty));
    }

    loop {
        let mut hasher = Sha256::new();
        hasher.update(prefix_bytes);
        hasher.update(nonce.to_string().as_bytes());
        let result = hasher.finalize();
        let hash = hex::encode(result);
        
        if hash.starts_with(&target) {
            return Ok((nonce, hash));
        }
        
        if nonce % 10000 == 0 {
             std::thread::yield_now();
        }
        
        nonce += 1;
        if nonce == u64::MAX {
             return Err("Mining failed: nonce overflow".to_string());
        }
    }
}

pub fn secure_nuke_database(db_path: &std::path::Path) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write;

    if db_path.exists() {
        let size = std::fs::metadata(db_path).map(|m| m.len()).unwrap_or(1024 * 1024);
        let mut rng = thread_rng();
        
        for _ in 0..3 {
            let mut file = OpenOptions::new().write(true).open(db_path).map_err(|e| e.to_string())?;
            let mut remaining = size;
            let chunk_size = 1024 * 1024;
            let mut junk = vec![0u8; chunk_size];
            
            while remaining > 0 {
                let to_write = std::cmp::min(remaining, chunk_size as u64);
                rng.fill_bytes(&mut junk[..to_write as usize]);
                file.write_all(&junk[..to_write as usize]).map_err(|e| e.to_string())?;
                remaining -= to_write;
            }
            file.sync_all().map_err(|e| e.to_string())?;
        }
        
        
        let file = OpenOptions::new().write(true).open(db_path).map_err(|e| e.to_string())?;
        file.set_len(0).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);

        
        let mut random_name = [0u8; 16];
        rng.fill_bytes(&mut random_name);
        let new_path = db_path.with_file_name(hex::encode(random_name));
        let _ = std::fs::rename(db_path, &new_path);
        
        std::fs::remove_file(new_path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

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

        
        let mut state = SessionState::load_from_db(&conn_bob, "alice").unwrap().unwrap();
        
        assert_eq!(state.skipped_message_keys.len(), 2);

        
        let dec1 = ratchet_decrypt(&conn_bob, "alice", &msg1).unwrap();
        assert_eq!(dec1, "Message 1");
        
        
        let dec2 = ratchet_decrypt(&conn_bob, "alice", &msg2).unwrap();
        assert_eq!(dec2, "Message 2");

        
        state = SessionState::load_from_db(&conn_bob, "alice").unwrap().unwrap();
        assert_eq!(state.skipped_message_keys.len(), 0);
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

        let mut ik_peer = "".to_string();

        
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
        };

        
        let dist_msg = create_group_distribution_message(&alice_gs).unwrap();

        
        let mut bob_gs = GroupState {
            group_id: "test_group".to_string(),
            my_sender_key: Some(create_group_sender_key()),
            member_sender_keys: HashMap::new(),
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
        
        let recipient_pq_sk = kyber1024::SecretKey::from_bytes(&decode_b64(&id_recipient.identity_keys.pq_private_key).unwrap()).unwrap();

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
        
        
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", seed, context).as_bytes());
        hasher.update(nonce.to_string().as_bytes());
        let result = hasher.finalize();
        assert_eq!(hex::encode(result), hash);
    }
}
