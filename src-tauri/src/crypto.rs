use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use x25519_dalek::{StaticSecret, PublicKey as XPublicKey};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as PQPublicKeyTrait, SecretKey as PQSecretKeyTrait, Ciphertext as PQCiphertextTrait, SharedSecret as PQSharedSecretTrait};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use rand::RngCore;
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

pub struct IdentityKeyPair {
    pub registration_id: u32,
    pub signing_key: SigningKey,
    pub diffie_hellman: [u8; 32],
    pub pq_sk: [u8; 3168],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyBundle {
    pub identity_hash: String,
    #[serde(rename = "registrationId")]
    pub registration_id: u32,
    #[serde(rename = "identityKey")]
    pub identity_key: String,
    #[serde(rename = "xy_identityKey", default)]
    pub xy_identity_key: String,
    #[serde(rename = "pq_identityKey")]
    pub pq_identity_key: String,
    #[serde(rename = "signedPreKey")]
    pub signed_pre_key: SignedPreKeyBundle,
    #[serde(rename = "preKeys")]
    pub pre_keys: Vec<PreKeyBundle>,
    #[serde(rename = "bundle_signature")]
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SignedPreKeyBundle {
    #[serde(rename = "keyId")]
    pub id: u32,
    #[serde(rename = "pq_publicKey")]
    pub pq_public_key: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PreKeyBundle {
    #[serde(rename = "keyId")]
    pub id: u32,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedEnvelope {
    #[serde(rename = "target_hash")]
    pub target_hash: String,
    pub sender_identity_key: String,
    pub ephemeral_key: String,
    #[serde(rename = "pq_ciphertext")]
    pub pq_ciphertext: String,
    pub payload: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InnerPayload {
    #[serde(rename = "sender_hash")]
    pub sender_hash: String,
    pub sender_identity_key: String,
    pub lh: String,
    pub ratchet_header: RatchetHeader,
    pub ciphertext: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RatchetHeader {
    pub public_key: String,
    pub n: u32,
    pub pn: u32,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SessionState {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub dh_secret: [u8; 32],
    pub remote_dh_pub: [u8; 32],
    pub n_send: u32,
    pub n_recv: u32,
    pub pn: u32,
    pub last_sent_hash: String,
    pub last_recv_hash: String,
}

pub fn generate_identity() -> IdentityKeyPair {
    let mut rng = rand::rngs::OsRng;
    let registration_id = rng.next_u32() % 16383;
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    
    let mut dh_bytes = [0u8; 32];
    rng.fill_bytes(&mut dh_bytes);
    
    let (_pq_pk, pq_sk) = kyber1024::keypair();
    
    IdentityKeyPair {
        registration_id,
        signing_key,
        diffie_hellman: dh_bytes,
        pq_sk: PQSecretKeyTrait::as_bytes(&pq_sk).try_into().unwrap(),
    }
}

pub fn derive_identity_hash(verifying_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn init_pqxdh_bob(identity: &IdentityKeyPair) -> (KeyBundle, [u8; 32], [u8; 3168]) {
    let mut rng = rand::rngs::OsRng;
    
    let mut spk_bytes = [0u8; 32];
    rng.fill_bytes(&mut spk_bytes);
    let spk_public = XPublicKey::from(spk_bytes);
    
    let (pq_spk_pub, pq_spk_sec) = kyber1024::keypair();
    let (pq_ik_pub, _pq_ik_sec) = kyber1024::keypair();

    let identity_dh_pub = XPublicKey::from(identity.diffie_hellman);
    let identity_key_b64 = BASE64.encode(identity.signing_key.verifying_key().as_bytes());
    let xy_identity_key_b64 = BASE64.encode(identity_dh_pub.as_bytes());
    let pq_ik_pub_b64 = BASE64.encode(PQPublicKeyTrait::as_bytes(&pq_ik_pub));
    let spk_public_b64 = BASE64.encode(spk_public.as_bytes());
    let pq_spk_pub_b64 = BASE64.encode(PQPublicKeyTrait::as_bytes(&pq_spk_pub));

    // 1. Internal SPK signature (over raw bytes)
    let mut spk_to_sign = Vec::new();
    spk_to_sign.extend_from_slice(identity.signing_key.verifying_key().as_bytes());
    spk_to_sign.extend_from_slice(spk_public.as_bytes());
    spk_to_sign.extend_from_slice(PQPublicKeyTrait::as_bytes(&pq_ik_pub));
    spk_to_sign.extend_from_slice(PQPublicKeyTrait::as_bytes(&pq_spk_pub));
    let spk_sig = identity.signing_key.sign(&spk_to_sign);
    let spk_sig_b64 = BASE64.encode(spk_sig.to_bytes());
    
    // Server order for SignedPreKeyBundle fields: keyId, pq_publicKey, publicKey, signature
    let spk_bundle = SignedPreKeyBundle {
        id: 1,
        pq_public_key: pq_spk_pub_b64.clone(),
        public_key: spk_public_b64.clone(),
        signature: spk_sig_b64.clone(),
    };

    // 2. Bundle signature over JSON (MANDATORY: match server's boost::json::serialize output)
    // Server builds an object with 4 fields in this exact order: 
    // identityKey, pq_identityKey, signedPreKey, preKeys
    let spk_json = serde_json::to_string(&spk_bundle).unwrap();
    let sign_data = format!(
        "{{\"identityKey\":\"{}\",\"pq_identityKey\":\"{}\",\"signedPreKey\":{},\"preKeys\":[]}}",
        identity_key_b64, pq_ik_pub_b64, spk_json
    );
    
    let bundle_signature = identity.signing_key.sign(sign_data.as_bytes());

    let id_hash = derive_identity_hash(&identity.signing_key.verifying_key());
    
    let bundle = KeyBundle {
        identity_hash: id_hash,
        registration_id: identity.registration_id,
        identity_key: identity_key_b64,
        xy_identity_key: xy_identity_key_b64,
        pq_identity_key: pq_ik_pub_b64,
        signed_pre_key: spk_bundle,
        pre_keys: vec![],
        signature: BASE64.encode(bundle_signature.to_bytes()),
    };

    (bundle, spk_bytes, PQSecretKeyTrait::as_bytes(&pq_spk_sec).try_into().unwrap())
}

pub fn establish_session_alice(
    identity: &IdentityKeyPair,
    bob_bundle: &KeyBundle
) -> (SessionState, SealedEnvelope) {
    let mut rng = rand::rngs::OsRng;
    
    let mut ek_bytes = [0u8; 32];
    rng.fill_bytes(&mut ek_bytes);
    let ek_a_public = XPublicKey::from(ek_bytes);

    let ik_b_bytes = if !bob_bundle.xy_identity_key.is_empty() {
         BASE64.decode(&bob_bundle.xy_identity_key).unwrap()
    } else {
         BASE64.decode(&bob_bundle.identity_key).unwrap()
    };
    let ik_b_pub = XPublicKey::from(<[u8; 32]>::try_from(&ik_b_bytes[..32]).unwrap());
    
    let spk_b_bytes = BASE64.decode(&bob_bundle.signed_pre_key.public_key).unwrap();
    let spk_b_pub = XPublicKey::from(<[u8; 32]>::try_from(&spk_b_bytes[..32]).unwrap());
    
    let pq_ik_b_bytes = BASE64.decode(&bob_bundle.pq_identity_key).unwrap();
    let pq_ik_b_pub = kyber1024::PublicKey::from_bytes(&pq_ik_b_bytes).unwrap();
    
    let pq_spk_b_bytes = BASE64.decode(&bob_bundle.signed_pre_key.pq_public_key).unwrap();
    let pq_spk_b_pub = kyber1024::PublicKey::from_bytes(&pq_spk_b_bytes).unwrap();
    
    let (pq_ss_1, pq_ct_1) = kyber1024::encapsulate(&pq_ik_b_pub);
    let (pq_ss_2, pq_ct_2) = kyber1024::encapsulate(&pq_spk_b_pub);

    let dh1 = StaticSecret::from(identity.diffie_hellman).diffie_hellman(&spk_b_pub);
    let dh2 = StaticSecret::from(ek_bytes).diffie_hellman(&ik_b_pub);
    let dh3 = StaticSecret::from(ek_bytes).diffie_hellman(&spk_b_pub);
    
    let mut km = Vec::new();
    km.extend_from_slice(dh1.as_bytes());
    km.extend_from_slice(dh2.as_bytes());
    km.extend_from_slice(dh3.as_bytes());
    km.extend_from_slice(PQSharedSecretTrait::as_bytes(&pq_ss_1));
    km.extend_from_slice(PQSharedSecretTrait::as_bytes(&pq_ss_2));
    
    let h = Hkdf::<Sha256>::new(None, &km);
    let mut root_key = [0u8; 32];
    h.expand(b"EntropyV1 X3DH+PQ", &mut root_key).unwrap();
    
    let state = SessionState {
        root_key,
        send_chain_key: root_key,
        recv_chain_key: [0u8; 32],
        dh_secret: ek_bytes,
        remote_dh_pub: *spk_b_pub.as_bytes(),
        n_send: 0,
        n_recv: 0,
        pn: 0,
        last_sent_hash: String::new(),
        last_recv_hash: String::new(),
    };

    let mut combined_pq_ct = Vec::new();
    combined_pq_ct.extend_from_slice(PQCiphertextTrait::as_bytes(&pq_ct_1));
    combined_pq_ct.extend_from_slice(PQCiphertextTrait::as_bytes(&pq_ct_2));
    
    let envelope = SealedEnvelope {
        target_hash: bob_bundle.identity_hash.clone(),
        sender_identity_key: BASE64.encode(identity.signing_key.verifying_key().as_bytes()),
        ephemeral_key: BASE64.encode(ek_a_public.as_bytes()),
        pq_ciphertext: BASE64.encode(&combined_pq_ct),
        payload: String::new(),
    };
    
    (state, envelope)
}

pub fn establish_session_bob(
    identity: &IdentityKeyPair,
    spk_sk: [u8; 32],
    pq_spk_sk: [u8; 3168],
    envelope: &SealedEnvelope
) -> Result<SessionState, String> {
    let ik_a_bytes = BASE64.decode(&envelope.sender_identity_key).map_err(|e| e.to_string())?;
    if ik_a_bytes.len() < 32 { return Err("Invalid sender identity key length".into()); }
    let ik_a_pub = XPublicKey::from(<[u8; 32]>::try_from(&ik_a_bytes[..32]).unwrap());
    
    let ek_a_bytes = BASE64.decode(&envelope.ephemeral_key).map_err(|e| e.to_string())?;
    if ek_a_bytes.len() < 32 { return Err("Invalid ephemeral key length".into()); }
    let ek_a_pub = XPublicKey::from(<[u8; 32]>::try_from(&ek_a_bytes[..32]).unwrap());
    
    let pq_ct_bytes = BASE64.decode(&envelope.pq_ciphertext).map_err(|e| e.to_string())?;
    if pq_ct_bytes.len() < 1568 * 2 { return Err("Invalid PQ ciphertext".into()); }
    
    let (pq_ct_1_bytes, pq_ct_2_bytes) = pq_ct_bytes.split_at(1568);
    let pq_ct_1 = kyber1024::Ciphertext::from_bytes(pq_ct_1_bytes).unwrap();
    let pq_ct_2 = kyber1024::Ciphertext::from_bytes(pq_ct_2_bytes).unwrap();
    
    let pq_ik_sk = kyber1024::SecretKey::from_bytes(&identity.pq_sk).unwrap();
    let pq_spk_sk_obj = kyber1024::SecretKey::from_bytes(&pq_spk_sk).unwrap();
    
    let pq_ss_1 = kyber1024::decapsulate(&pq_ct_1, &pq_ik_sk);
    let pq_ss_2 = kyber1024::decapsulate(&pq_ct_2, &pq_spk_sk_obj);
    
    let dh1 = StaticSecret::from(spk_sk).diffie_hellman(&ik_a_pub);
    let dh2 = StaticSecret::from(identity.diffie_hellman).diffie_hellman(&ek_a_pub);
    let dh3 = StaticSecret::from(spk_sk).diffie_hellman(&ek_a_pub);
    
    let mut km = Vec::new();
    km.extend_from_slice(dh1.as_bytes());
    km.extend_from_slice(dh2.as_bytes());
    km.extend_from_slice(dh3.as_bytes());
    km.extend_from_slice(PQSharedSecretTrait::as_bytes(&pq_ss_1));
    km.extend_from_slice(PQSharedSecretTrait::as_bytes(&pq_ss_2));
    
    let h = Hkdf::<Sha256>::new(None, &km);
    let mut root_key = [0u8; 32];
    h.expand(b"EntropyV1 X3DH+PQ", &mut root_key).unwrap();
    
    Ok(SessionState {
        root_key,
        send_chain_key: [0u8; 32],
        recv_chain_key: root_key,
        dh_secret: [0u8; 32],
        remote_dh_pub: *ek_a_pub.as_bytes(),
        n_send: 0,
        n_recv: 0,
        pn: 0,
        last_sent_hash: String::new(),
        last_recv_hash: String::new(),
    })
}

pub fn encrypt_message(
    state: &mut SessionState,
    identity: &IdentityKeyPair,
    message: &str
) -> SealedEnvelope {
    let mut hasher = Sha256::new();
    hasher.update(&state.send_chain_key);
    state.send_chain_key = hasher.finalize().into();
    
    let h = Hkdf::<Sha256>::new(None, &state.send_chain_key);
    let mut msg_key = [0u8; 32];
    h.expand(b"Entropy Message Key", &mut msg_key).unwrap();
    
    let msg_bytes = message.as_bytes();
    let msg_len = msg_bytes.len() as u32;
    let mut padded_msg = msg_len.to_be_bytes().to_vec();
    padded_msg.extend_from_slice(msg_bytes);
    
    let target_len = if padded_msg.len() <= 512 { 512 }
                 else if padded_msg.len() <= 1024 { 1024 }
                 else if padded_msg.len() <= 5120 { 5120 }
                 else { (padded_msg.len() + 1023) / 1024 * 1024 };
    
    if padded_msg.len() < target_len {
        let mut padding = vec![0u8; target_len - padded_msg.len()];
        rand::rngs::OsRng.fill_bytes(&mut padding);
        padded_msg.extend_from_slice(&padding);
    }

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&msg_key));
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, &padded_msg[..]).unwrap();
    let mut final_ct = nonce_bytes.to_vec();
    final_ct.extend_from_slice(&ciphertext);

    let header = RatchetHeader {
        public_key: BASE64.encode(XPublicKey::from(state.dh_secret).as_bytes()),
        n: state.n_send,
        pn: state.pn,
    };
    
    state.n_send += 1;

    let mut inner = InnerPayload {
        sender_hash: derive_identity_hash(&identity.signing_key.verifying_key()),
        sender_identity_key: BASE64.encode(XPublicKey::from(identity.diffie_hellman).as_bytes()),
        lh: state.last_sent_hash.clone(),
        ratchet_header: header,
        ciphertext: BASE64.encode(&final_ct),
        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
    };
    
    let mut result_hasher = Sha256::new();
    result_hasher.update(&final_ct);
    state.last_sent_hash = hex::encode(result_hasher.finalize());
    inner.lh = state.last_sent_hash.clone(); 

    let inner_json = serde_json::to_string(&inner).unwrap();
    
    SealedEnvelope {
        target_hash: String::new(),
        sender_identity_key: String::new(),
        ephemeral_key: String::new(),
        pq_ciphertext: String::new(),
        payload: BASE64.encode(inner_json.as_bytes()),
    }
}

pub fn decrypt_envelope(
    _identity: &IdentityKeyPair,
    state: &mut SessionState,
    envelope: &SealedEnvelope
) -> Result<InnerPayload, String> {
    let inner_bytes = BASE64.decode(&envelope.payload).map_err(|e| e.to_string())?;
    let inner: InnerPayload = serde_json::from_slice(&inner_bytes).map_err(|e| e.to_string())?;
    
    let mut hasher = Sha256::new();
    hasher.update(&state.recv_chain_key);
    state.recv_chain_key = hasher.finalize().into();
    
    let h = Hkdf::<Sha256>::new(None, &state.recv_chain_key);
    let mut msg_key = [0u8; 32];
    h.expand(b"Entropy Message Key", &mut msg_key).unwrap();
    
    let ct_bytes = BASE64.decode(&inner.ciphertext).map_err(|e| e.to_string())?;
    if ct_bytes.len() < 12 { return Err("Invalid ciphertext".into()); }
    
    let (nonce_bytes, ciphertext) = ct_bytes.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&msg_key));
    let padded_plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;
    
    if padded_plaintext.len() < 4 { return Err("Invalid plaintext length".into()); }
    let msg_len = u32::from_be_bytes(padded_plaintext[0..4].try_into().unwrap()) as usize;
    if msg_len + 4 > padded_plaintext.len() { return Err("Invalid message length in prefix".into()); }
    
    let original_msg = &padded_plaintext[4..4+msg_len];
    
    let mut result_hasher = Sha256::new();
    result_hasher.update(&ct_bytes);
    state.last_recv_hash = hex::encode(result_hasher.finalize());

    let mut result = inner;
    result.ciphertext = String::from_utf8(original_msg.to_vec()).map_err(|e| e.to_string())?;
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_encryption_decryption() {
        // 1. Setup Bob
        let bob_identity = generate_identity();
        let (bob_bundle, bob_spk_sk, bob_pq_spk_sk) = init_pqxdh_bob(&bob_identity);

        // 2. Setup Alice & Establish Session
        let alice_identity = generate_identity();
        let (mut alice_state, mut envelope) = establish_session_alice(&alice_identity, &bob_bundle);

        // 3. Alice encrypts her first message
        let msg = "Hello from the post-quantum future!";
        let dr_envelope = encrypt_message(&mut alice_state, &alice_identity, msg);
        
        // Finalize envelope for Bob (Alice puts the encrypted DR payload into the X3DH envelope)
        envelope.payload = dr_envelope.payload;

        // 4. Bob receives the first message and establishes his session
        let mut bob_state = establish_session_bob(&bob_identity, bob_spk_sk, bob_pq_spk_sk, &envelope).expect("Bob session establishment failed");

        // 5. Bob decrypts
        let result = decrypt_envelope(&bob_identity, &mut bob_state, &envelope).expect("Decryption failed");
        
        assert_eq!(result.ciphertext, msg);
        println!("Decrypted message: {}", result.ciphertext);

        // 6. Test second message (Double Ratchet chain continuity)
        let msg2 = "Continuity check.";
        let dr_envelope2 = encrypt_message(&mut alice_state, &alice_identity, msg2);
        let mut envelope2 = SealedEnvelope {
            target_hash: "bob".into(),
            sender_identity_key: String::new(), 
            ephemeral_key: String::new(),
            pq_ciphertext: String::new(),
            payload: dr_envelope2.payload,
        };

        let result2 = decrypt_envelope(&bob_identity, &mut bob_state, &envelope2).expect("Second decryption failed");
        assert_eq!(result2.ciphertext, msg2);
    }
}
