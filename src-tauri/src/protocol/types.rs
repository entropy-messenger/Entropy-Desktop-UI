use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use rusqlite::{params, Connection};
use ed25519_dalek::{Keypair, Signer, PublicKey, SecretKey};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use rand::{RngCore, thread_rng};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as PQPubKey, SecretKey as PQSecretKey};
use crate::protocol::utils::encode_b64;

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
    pub is_chunked: bool,
    pub chunk_size: Option<u32>,
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
    pub members: Vec<String>,
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

    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            peer_hash TEXT,
            timestamp INTEGER,
            content TEXT,
            sender_hash TEXT,
            type TEXT,
            is_mine INTEGER,
            status TEXT,
            reply_to_id TEXT,
            attachment_json TEXT
        );",
        [],
    ).map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_hash);",
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

        if self.pre_keys.len() > 100 {
            let to_remove = self.pre_keys.len() - 100;
            self.pre_keys.drain(0..to_remove);
        }
    }
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
