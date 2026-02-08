
use rusqlite::{params, Connection};
use std::sync::MutexGuard;
use async_trait::async_trait;
use libsignal_protocol::{
    IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore, KyberPreKeyStore,
    ProtocolAddress, IdentityKeyPair, IdentityKey, Direction, IdentityChange,
    SignalProtocolError, KyberPreKeyId, PreKeyId, SignedPreKeyId, PublicKey,
    PreKeyRecord, SessionRecord, SignedPreKeyRecord, KyberPreKeyRecord, GenericSignedPreKey
};
use crate::app_state::DbState;
#[derive(Clone)]
pub struct SqliteSignalStore<'a> {
    state: &'a DbState,
}


impl<'a> SqliteSignalStore<'a> {
    pub fn new(state: &'a DbState) -> Self {
        Self { state }
    }

    fn get_conn(&self) -> std::result::Result<MutexGuard<'_, Option<Connection>>, SignalProtocolError> {
        self.state.conn.lock().map_err(|e| {
            SignalProtocolError::InvalidArgument(format!("Mutex lock failed: {}", e))
        })
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqliteSignalStore<'_> {
    async fn get_identity_key_pair(&self) -> std::result::Result<IdentityKeyPair, SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let mut stmt = conn.prepare("SELECT public_key, private_key FROM signal_identity LIMIT 1")
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        
        let mut rows = stmt.query([])
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))? {
            let pub_bytes: Vec<u8> = row.get::<_, Vec<u8>>(0).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
            let priv_bytes: Vec<u8> = row.get::<_, Vec<u8>>(1).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
            
            let ik = IdentityKey::decode(&pub_bytes)?;
            let pk = libsignal_protocol::PrivateKey::deserialize(&priv_bytes)?;
            Ok(IdentityKeyPair::new(ik, pk))
        } else {
            Err(SignalProtocolError::InvalidState("IdentityKeyStore", "No identity key pair found".into()))
        }
    }

    async fn get_local_registration_id(&self) -> std::result::Result<u32, SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let mut stmt = conn.prepare("SELECT registration_id FROM signal_identity LIMIT 1")
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        let mut rows = stmt.query([])
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))? {
            Ok(row.get::<_, u32>(0).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?)
        } else {
            Err(SignalProtocolError::InvalidState("IdentityKeyStore", "No registration ID found".into()))
        }
    }

    async fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> std::result::Result<IdentityChange, SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let address_str = format!("{}:{}", address.name(), address.device_id());
        let pub_bytes = identity.serialize();

        // Check existing
        let mut stmt = conn.prepare("SELECT public_key FROM signal_identities_remote WHERE address = ?1")
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        let mut rows = stmt.query(params![address_str])
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;

        let change = if let Some(row) = rows.next().map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))? {
            let existing_pub: Vec<u8> = row.get::<_, Vec<u8>>(0).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
            if existing_pub == pub_bytes.as_ref() {
                IdentityChange::NewOrUnchanged
            } else {
                IdentityChange::ReplacedExisting
            }
        } else {
            IdentityChange::NewOrUnchanged
        };

        conn.execute(
            "INSERT OR REPLACE INTO signal_identities_remote (address, public_key) VALUES (?1, ?2)",
            params![address_str, pub_bytes.as_ref()],
        ).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        
        Ok(change)
    }

    async fn is_trusted_identity(&self, address: &ProtocolAddress, identity: &IdentityKey, _direction: Direction) -> std::result::Result<bool, SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let address_str = format!("{}:{}", address.name(), address.device_id());
        let mut stmt = conn.prepare("SELECT public_key FROM signal_identities_remote WHERE address = ?1")
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        let mut rows = stmt.query(params![address_str])
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))? {
            let stored_pub: Vec<u8> = row.get::<_, Vec<u8>>(0).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
            Ok(stored_pub == identity.serialize().as_ref())
        } else {
            // First time seeing this identity
            Ok(true)
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> std::result::Result<Option<IdentityKey>, SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let address_str = format!("{}:{}", address.name(), address.device_id());
        let mut stmt = conn.prepare("SELECT public_key FROM signal_identities_remote WHERE address = ?1")
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        let mut rows = stmt.query(params![address_str])
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))? {
            let pub_bytes: Vec<u8> = row.get::<_, Vec<u8>>(0).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
            Ok(Some(IdentityKey::decode(&pub_bytes)?))
        } else {
            Ok(None)
        }
    }
}

#[async_trait(?Send)]
impl SessionStore for SqliteSignalStore<'_> {
    async fn load_session(&self, address: &ProtocolAddress) -> std::result::Result<Option<SessionRecord>, SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let address_str = format!("{}:{}", address.name(), address.device_id());
        let mut stmt = conn.prepare("SELECT session_data FROM signal_sessions WHERE address = ?1")
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        let mut rows = stmt.query(params![address_str])
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))? {
            let data: Vec<u8> = row.get::<_, Vec<u8>>(0).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
            println!("[SignalStore] Loaded session for {}", address_str);
            Ok(Some(SessionRecord::deserialize(&data)?))
        } else {
            Ok(None)
        }
    }

    async fn store_session(&mut self, address: &ProtocolAddress, record: &SessionRecord) -> std::result::Result<(), SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let address_str = format!("{}:{}", address.name(), address.device_id());
        let data = record.serialize()?;

        println!("[SignalStore] Storing session for {}", address_str);
        conn.execute(
            "INSERT OR REPLACE INTO signal_sessions (address, session_data) VALUES (?1, ?2)",
            params![address_str, data],
        ).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        
        Ok(())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SqliteSignalStore<'_> {
    async fn get_pre_key(&self, pre_key_id: PreKeyId) -> std::result::Result<PreKeyRecord, SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let id_u32: u32 = pre_key_id.into();
        println!("[SignalStore] Loading PreKey {}", id_u32);
        let mut stmt = conn.prepare("SELECT key_data FROM signal_pre_keys WHERE key_id = ?1")
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        let mut rows = stmt.query(params![id_u32])
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))? {
            let data: Vec<u8> = row.get::<_, Vec<u8>>(0).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
            Ok(PreKeyRecord::deserialize(&data)?)
        } else {
            println!("[SignalStore] ERROR: PreKey {} not found!", id_u32);
            Err(SignalProtocolError::InvalidPreKeyId)
        }
    }

    async fn save_pre_key(&mut self, pre_key_id: PreKeyId, record: &PreKeyRecord) -> std::result::Result<(), SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let id_u32 = u32::from(pre_key_id);
        let data = record.serialize()?;

        println!("[SignalStore] Saving PreKey {}", id_u32);
        conn.execute(
            "INSERT OR REPLACE INTO signal_pre_keys (key_id, key_data) VALUES (?1, ?2)",
            params![id_u32, data],
        ).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        
        Ok(())
    }

    async fn remove_pre_key(&mut self, pre_key_id: PreKeyId) -> std::result::Result<(), SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let id_u32: u32 = pre_key_id.into();
        println!("[SignalStore] Removing PreKey {}", id_u32);
        conn.execute(
            "DELETE FROM signal_pre_keys WHERE key_id = ?1",
            params![id_u32],
        ).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqliteSignalStore<'_> {
    async fn get_signed_pre_key(&self, signed_pre_key_id: SignedPreKeyId) -> std::result::Result<SignedPreKeyRecord, SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let id_u32: u32 = signed_pre_key_id.into();
        let mut stmt = conn.prepare("SELECT key_data FROM signal_signed_pre_keys WHERE key_id = ?1")
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        let mut rows = stmt.query(params![id_u32])
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))? {
            let data: Vec<u8> = row.get::<_, Vec<u8>>(0).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
            Ok(SignedPreKeyRecord::deserialize(&data)?)
        } else {
            Err(SignalProtocolError::InvalidSignedPreKeyId)
        }
    }

    async fn save_signed_pre_key(&mut self, signed_pre_key_id: SignedPreKeyId, record: &SignedPreKeyRecord) -> std::result::Result<(), SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let id_u32: u32 = signed_pre_key_id.into();
        let data = record.serialize()?;

        conn.execute(
            "INSERT OR REPLACE INTO signal_signed_pre_keys (key_id, key_data) VALUES (?1, ?2)",
            params![id_u32, data],
        ).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SqliteSignalStore<'_> {
    async fn get_kyber_pre_key(&self, kyber_prekey_id: KyberPreKeyId) -> std::result::Result<KyberPreKeyRecord, SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let id_u32: u32 = kyber_prekey_id.into();
        println!("[SignalStore] Loading KyberPreKey {}", id_u32);
        let mut stmt = conn.prepare("SELECT key_data FROM signal_kyber_pre_keys WHERE key_id = ?1")
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        let mut rows = stmt.query(params![id_u32])
            .map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))? {
            let data: Vec<u8> = row.get::<_, Vec<u8>>(0).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
            Ok(KyberPreKeyRecord::deserialize(&data)?)
        } else {
            println!("[SignalStore] ERROR: KyberPreKey {} not found!", id_u32);
            Err(SignalProtocolError::InvalidKyberPreKeyId)
        }
    }

    async fn save_kyber_pre_key(&mut self, kyber_prekey_id: KyberPreKeyId, record: &KyberPreKeyRecord) -> std::result::Result<(), SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let id_u32: u32 = kyber_prekey_id.into();
        let data = record.serialize()?;

        println!("[SignalStore] Saving KyberPreKey {}", id_u32);
        conn.execute(
            "INSERT OR REPLACE INTO signal_kyber_pre_keys (key_id, key_data) VALUES (?1, ?2)",
            params![id_u32, data],
        ).map_err(|e: rusqlite::Error| SignalProtocolError::InvalidArgument(e.to_string()))?;
        
        Ok(())
    }

    async fn mark_kyber_pre_key_used(&mut self, kyber_prekey_id: KyberPreKeyId, ec_prekey_id: SignedPreKeyId, base_key: &PublicKey) -> std::result::Result<(), SignalProtocolError> {
        let lock = self.get_conn()?;
        let conn = lock.as_ref().ok_or(SignalProtocolError::InvalidArgument("DB not initialized".into()))?;
        
        let kyber_id: u32 = kyber_prekey_id.into();
        let ec_id: u32 = ec_prekey_id.into();
        let base_bytes = base_key.serialize();

        conn.execute(
            "INSERT INTO signal_kyber_base_keys_seen (kyber_prekey_id, ec_prekey_id, base_key) VALUES (?1, ?2, ?3)",
            params![kyber_id, ec_id, base_bytes.as_ref()],
        ).map_err(|e: rusqlite::Error| {
            if e.to_string().contains("UNIQUE constraint failed") {
                SignalProtocolError::InvalidMessage(libsignal_protocol::CiphertextMessageType::PreKey, "reused base key".into())
            } else {
                SignalProtocolError::InvalidArgument(e.to_string())
            }
        })?;
        
        Ok(())
    }
}
