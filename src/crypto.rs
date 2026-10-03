use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use sha2::Sha256;
use std::sync::Mutex;

use crate::db::Database;
use crate::errors::{AppError, AppResult};

/// Handles sealing and unsealing of vault keys at rest.
///
/// Design (independent implementation — shares no code with any proprietary project):
///   - A random 256-bit AES symmetric key (the "wrapping secret") seals/unseals vault keys via AES-256-GCM.
///   - The wrapping secret itself is protected by an RSA key pair and persisted in the database.
///   - On startup, the RSA key recovers the wrapping secret into memory.
pub struct VaultKeyManager {
    rsa_private: RsaPrivateKey,
    rsa_public: RsaPublicKey,
    wrapping_secret: Mutex<Option<Vec<u8>>>,
}

impl VaultKeyManager {
    pub fn new(private_pem: &str, public_pem: &str) -> AppResult<Self> {
        let rsa_private = RsaPrivateKey::from_pkcs8_pem(private_pem)
            .map_err(|e| AppError::CryptoError(format!("Failed to load RSA private key: {e}")))?;
        let rsa_public = RsaPublicKey::from_public_key_pem(public_pem)
            .map_err(|e| AppError::CryptoError(format!("Failed to load RSA public key: {e}")))?;

        Ok(Self {
            rsa_private,
            rsa_public,
            wrapping_secret: Mutex::new(None),
        })
    }

    /// Recover or create the wrapping secret used to seal/unseal vault keys.
    /// If the DB already has a persisted (RSA-protected) secret, recover it.
    /// Otherwise, generate a fresh one and persist it.
    pub fn bootstrap_wrapping_key(&self, db: &Database) -> AppResult<()> {
        let mut ws = self.wrapping_secret.lock().map_err(|e| AppError::InternalError(e.to_string()))?;

        let stored = db.get_app_data("wrapping_secret_enc")?;

        if let Some(wrapped_b64) = stored {
            let wrapped = B64.decode(&wrapped_b64)
                .map_err(|e| AppError::CryptoError(format!("Invalid base64 in stored wrapping secret: {e}")))?;
            let recovered = self.unwrap_with_rsa(&wrapped)?;
            *ws = Some(recovered);
            tracing::info!("Wrapping secret recovered from database");
        } else {
            let mut fresh = vec![0u8; 32];
            OsRng.fill_bytes(&mut fresh);

            let protected = self.wrap_with_rsa(&fresh)?;
            let protected_b64 = B64.encode(&protected);
            db.set_app_data("wrapping_secret_enc", &protected_b64)?;

            *ws = Some(fresh);
            tracing::info!("Fresh wrapping secret generated and persisted");
        }

        Ok(())
    }

    /// Seal a vault key (base64 string) for persistent storage.
    /// Returns: nonce (12 bytes) || ciphertext, all as raw bytes.
    pub fn seal_vault_key(&self, plaintext_b64: &str) -> AppResult<Vec<u8>> {
        let plaintext = B64.decode(plaintext_b64)
            .map_err(|e| AppError::CryptoError(format!("Invalid base64 vault key: {e}")))?;

        let mk = self.get_wrapping_secret()?;
        let cipher = Aes256Gcm::new_from_slice(&mk)
            .map_err(|e| AppError::CryptoError(format!("AES init failed: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| AppError::CryptoError(format!("AES encrypt failed: {e}")))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Unseal a vault key from storage. Input: nonce (12 bytes) || ciphertext.
    /// Returns the original base64-encoded key.
    pub fn unseal_vault_key(&self, sealed: &[u8]) -> AppResult<String> {
        if sealed.len() < 13 {
            return Err(AppError::CryptoError("Sealed data too short".to_string()));
        }

        let (nonce_bytes, ciphertext) = sealed.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let mk = self.get_wrapping_secret()?;
        let cipher = Aes256Gcm::new_from_slice(&mk)
            .map_err(|e| AppError::CryptoError(format!("AES init failed: {e}")))?;

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| AppError::CryptoError(format!("AES decrypt failed: {e}")))?;

        Ok(B64.encode(&plaintext))
    }

    /// Rotate the wrapping secret: decrypt all user keys with the current secret,
    /// generate a fresh secret, re-encrypt everything, and commit atomically.
    /// If any step fails, the database is left completely unchanged.
    pub fn rotate_wrapping_secret(&self, db: &Database) -> AppResult<usize> {
        // 1. Read all encrypted key blobs
        let all_keys = db.get_all_encrypted_keys()?;
        let count = all_keys.len();

        if count == 0 {
            tracing::info!("No user keys to rotate — generating fresh wrapping secret only");
        }

        // 2. Decrypt every key with the CURRENT wrapping secret
        let old_secret = self.get_wrapping_secret()?;
        let old_cipher = Aes256Gcm::new_from_slice(&old_secret)
            .map_err(|e| AppError::CryptoError(format!("Old AES init failed: {e}")))?;

        let mut plaintext_keys: Vec<(uuid::Uuid, Vec<u8>)> = Vec::with_capacity(count);
        for (user_id, sealed) in &all_keys {
            if sealed.len() < 13 {
                return Err(AppError::CryptoError(format!(
                    "Sealed data too short for user {user_id} — aborting rotation"
                )));
            }
            let (nonce_bytes, ciphertext) = sealed.split_at(12);
            let nonce = Nonce::from_slice(nonce_bytes);
            let plaintext = old_cipher.decrypt(nonce, ciphertext).map_err(|e| {
                AppError::CryptoError(format!(
                    "Failed to decrypt key for user {user_id} with current secret: {e} — aborting rotation"
                ))
            })?;
            plaintext_keys.push((*user_id, plaintext));
        }

        // 3. Generate a fresh 256-bit wrapping secret
        let mut new_secret = vec![0u8; 32];
        OsRng.fill_bytes(&mut new_secret);
        let new_cipher = Aes256Gcm::new_from_slice(&new_secret)
            .map_err(|e| AppError::CryptoError(format!("New AES init failed: {e}")))?;

        // 4. Re-encrypt every key with the new secret
        let mut re_encrypted: Vec<(uuid::Uuid, Vec<u8>)> = Vec::with_capacity(count);
        for (user_id, plaintext) in &plaintext_keys {
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ciphertext = new_cipher.encrypt(nonce, plaintext.as_ref()).map_err(|e| {
                AppError::CryptoError(format!(
                    "Failed to re-encrypt key for user {user_id}: {e} — aborting rotation"
                ))
            })?;
            let mut blob = nonce_bytes.to_vec();
            blob.extend_from_slice(&ciphertext);
            re_encrypted.push((*user_id, blob));
        }

        // 5. RSA-wrap the new secret
        let wrapped = self.wrap_with_rsa(&new_secret)?;
        let wrapped_b64 = B64.encode(&wrapped);

        // 6. Verify the RSA wrap roundtrips before committing
        let verify = self.unwrap_with_rsa(&wrapped)?;
        if verify != new_secret {
            return Err(AppError::CryptoError(
                "RSA wrap/unwrap verification failed — aborting rotation".to_string(),
            ));
        }

        // 7. Atomic DB commit: all key blobs + new wrapped secret
        db.rotate_all_keys_atomic(&re_encrypted, &wrapped_b64)?;

        // 8. Update in-memory wrapping secret
        let mut ws = self.wrapping_secret.lock().map_err(|e| AppError::InternalError(e.to_string()))?;
        *ws = Some(new_secret);

        tracing::info!("Wrapping secret rotated successfully — {count} user key(s) re-encrypted");
        Ok(count)
    }

    fn get_wrapping_secret(&self) -> AppResult<Vec<u8>> {
        let ws = self.wrapping_secret.lock().map_err(|e| AppError::InternalError(e.to_string()))?;
        ws.clone().ok_or_else(|| AppError::CryptoError("Wrapping secret not initialized".to_string()))
    }

    fn wrap_with_rsa(&self, data: &[u8]) -> AppResult<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        let mut rng = rand::thread_rng();
        self.rsa_public
            .encrypt(&mut rng, padding, data)
            .map_err(|e| AppError::CryptoError(format!("RSA wrap failed: {e}")))
    }

    fn unwrap_with_rsa(&self, data: &[u8]) -> AppResult<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        self.rsa_private
            .decrypt(padding, data)
            .map_err(|e| AppError::CryptoError(format!("RSA unwrap failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

    fn generate_test_keypair() -> (String, String) {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        let public_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        (private_pem, public_pem)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (priv_pem, pub_pem) = generate_test_keypair();
        let mgr = VaultKeyManager::new(&priv_pem, &pub_pem).unwrap();

        // Manually set a wrapping secret for testing
        {
            let mut ws = mgr.wrapping_secret.lock().unwrap();
            let mut key = vec![0u8; 32];
            OsRng.fill_bytes(&mut key);
            *ws = Some(key);
        }

        let original = B64.encode(b"this-is-a-test-user-encryption-key");
        let sealed = mgr.seal_vault_key(&original).unwrap();
        let decrypted = mgr.unseal_vault_key(&sealed).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_rsa_wrap_unwrap_roundtrip() {
        let (priv_pem, pub_pem) = generate_test_keypair();
        let mgr = VaultKeyManager::new(&priv_pem, &pub_pem).unwrap();

        let data = b"hello world secret data";
        let wrapped = mgr.wrap_with_rsa(data).unwrap();
        let unwrapped = mgr.unwrap_with_rsa(&wrapped).unwrap();

        assert_eq!(data.to_vec(), unwrapped);
    }

    #[test]
    fn test_unseal_too_short_data() {
        let (priv_pem, pub_pem) = generate_test_keypair();
        let mgr = VaultKeyManager::new(&priv_pem, &pub_pem).unwrap();

        {
            let mut ws = mgr.wrapping_secret.lock().unwrap();
            *ws = Some(vec![0u8; 32]);
        }

        let result = mgr.unseal_vault_key(&[0u8; 5]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unseal_tampered_data() {
        let (priv_pem, pub_pem) = generate_test_keypair();
        let mgr = VaultKeyManager::new(&priv_pem, &pub_pem).unwrap();

        {
            let mut ws = mgr.wrapping_secret.lock().unwrap();
            let mut key = vec![0u8; 32];
            OsRng.fill_bytes(&mut key);
            *ws = Some(key);
        }

        let original = B64.encode(b"test-key");
        let mut sealed = mgr.seal_vault_key(&original).unwrap();
        // Tamper with the sealed data
        if let Some(last) = sealed.last_mut() {
            *last ^= 0xFF;
        }
        let result = mgr.unseal_vault_key(&sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_rotation_preserves_all_user_keys() {
        let (priv_pem, pub_pem) = generate_test_keypair();
        let mgr = VaultKeyManager::new(&priv_pem, &pub_pem).unwrap();
        let db = crate::db::Database::open(":memory:").unwrap();
        mgr.bootstrap_wrapping_key(&db).unwrap();

        // Enroll 5 users with distinct keys
        let mut users = Vec::new();
        for i in 0..5 {
            let uid = uuid::Uuid::new_v4();
            let original_key = B64.encode(format!("user-{i}-vault-key-{}", uid).as_bytes());
            let sealed = mgr.seal_vault_key(&original_key).unwrap();
            db.insert_user_key(&uid, &sealed).unwrap();
            users.push((uid, original_key));
        }

        // Rotate the wrapping secret
        let count = mgr.rotate_wrapping_secret(&db).unwrap();
        assert_eq!(count, 5, "All 5 keys should have been rotated");

        // Verify every user's key is still readable and unchanged
        for (uid, original_key) in &users {
            let record = db.get_user_key(uid).unwrap().unwrap();
            let decrypted = mgr.unseal_vault_key(&record.encrypted_key).unwrap();
            assert_eq!(&decrypted, original_key, "Key for user {uid} must survive rotation");
        }
    }

    #[test]
    fn test_rotation_with_zero_keys() {
        let (priv_pem, pub_pem) = generate_test_keypair();
        let mgr = VaultKeyManager::new(&priv_pem, &pub_pem).unwrap();
        let db = crate::db::Database::open(":memory:").unwrap();
        mgr.bootstrap_wrapping_key(&db).unwrap();

        // Rotating with no users should succeed and return 0
        let count = mgr.rotate_wrapping_secret(&db).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_double_rotation_preserves_keys() {
        let (priv_pem, pub_pem) = generate_test_keypair();
        let mgr = VaultKeyManager::new(&priv_pem, &pub_pem).unwrap();
        let db = crate::db::Database::open(":memory:").unwrap();
        mgr.bootstrap_wrapping_key(&db).unwrap();

        // Enroll 3 users
        let mut users = Vec::new();
        for i in 0..3 {
            let uid = uuid::Uuid::new_v4();
            let original_key = B64.encode(format!("double-rotation-key-{i}").as_bytes());
            let sealed = mgr.seal_vault_key(&original_key).unwrap();
            db.insert_user_key(&uid, &sealed).unwrap();
            users.push((uid, original_key));
        }

        // Rotate TWICE
        mgr.rotate_wrapping_secret(&db).unwrap();
        mgr.rotate_wrapping_secret(&db).unwrap();

        // All keys must still be correct
        for (uid, original_key) in &users {
            let record = db.get_user_key(uid).unwrap().unwrap();
            let decrypted = mgr.unseal_vault_key(&record.encrypted_key).unwrap();
            assert_eq!(&decrypted, original_key, "Key for {uid} must survive double rotation");
        }
    }

    #[test]
    fn test_rotation_records_timestamp() {
        let (priv_pem, pub_pem) = generate_test_keypair();
        let mgr = VaultKeyManager::new(&priv_pem, &pub_pem).unwrap();
        let db = crate::db::Database::open(":memory:").unwrap();
        mgr.bootstrap_wrapping_key(&db).unwrap();

        // No timestamp before rotation
        assert!(db.get_app_data("last_rotation_at").unwrap().is_none());

        mgr.rotate_wrapping_secret(&db).unwrap();

        // Timestamp must exist after rotation
        let ts = db.get_app_data("last_rotation_at").unwrap();
        assert!(ts.is_some(), "Rotation timestamp must be recorded");
    }

    #[test]
    fn test_new_keys_work_after_rotation() {
        let (priv_pem, pub_pem) = generate_test_keypair();
        let mgr = VaultKeyManager::new(&priv_pem, &pub_pem).unwrap();
        let db = crate::db::Database::open(":memory:").unwrap();
        mgr.bootstrap_wrapping_key(&db).unwrap();

        // Enroll a key before rotation
        let uid_before = uuid::Uuid::new_v4();
        let key_before = B64.encode(b"key-before-rotation");
        let sealed = mgr.seal_vault_key(&key_before).unwrap();
        db.insert_user_key(&uid_before, &sealed).unwrap();

        // Rotate
        mgr.rotate_wrapping_secret(&db).unwrap();

        // Enroll a NEW key after rotation
        let uid_after = uuid::Uuid::new_v4();
        let key_after = B64.encode(b"key-after-rotation");
        let sealed_after = mgr.seal_vault_key(&key_after).unwrap();
        db.insert_user_key(&uid_after, &sealed_after).unwrap();

        // Both keys must be readable
        let rec_before = db.get_user_key(&uid_before).unwrap().unwrap();
        assert_eq!(mgr.unseal_vault_key(&rec_before.encrypted_key).unwrap(), key_before);

        let rec_after = db.get_user_key(&uid_after).unwrap().unwrap();
        assert_eq!(mgr.unseal_vault_key(&rec_after.encrypted_key).unwrap(), key_after);
    }
}
