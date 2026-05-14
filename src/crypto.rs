use crate::error::{ArgosError, Result};
use crate::types::EncryptionConfig;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;

pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

pub fn passphrase_from_env() -> Result<Option<String>> {
    if let Ok(path) = std::env::var("ARGOSFS_KEY_FILE") {
        return Ok(Some(
            fs::read_to_string(path)?
                .trim_end_matches(['\r', '\n'])
                .to_string(),
        ));
    }
    Ok(std::env::var("ARGOSFS_KEY").ok())
}

pub fn new_encryption_config(passphrase: &str, aad: &[u8]) -> Result<EncryptionConfig> {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt)?;
    let marker = b"argosfs-key-check";
    let (nonce, ciphertext) = encrypt_with_key(&key, marker, aad)?;
    Ok(EncryptionConfig {
        enabled: true,
        kdf: "argon2id".to_string(),
        salt_hex: hex::encode(salt),
        key_check_nonce_hex: hex::encode(nonce),
        key_check_ciphertext_hex: hex::encode(ciphertext),
    })
}

pub fn derive_key_for_config(
    config: &EncryptionConfig,
    passphrase: &str,
    aad: &[u8],
) -> Result<[u8; 32]> {
    if config.kdf != "argon2id" {
        return Err(ArgosError::Invalid(format!(
            "unsupported encryption KDF: {}",
            config.kdf
        )));
    }
    let salt = hex::decode(&config.salt_hex)
        .map_err(|err| ArgosError::Invalid(format!("invalid encryption salt: {err}")))?;
    if salt.len() != SALT_LEN {
        return Err(ArgosError::Invalid(format!(
            "invalid encryption salt length: {}",
            salt.len()
        )));
    }
    let key = derive_key(passphrase, &salt)?;
    let nonce = hex::decode(&config.key_check_nonce_hex)
        .map_err(|err| ArgosError::Invalid(format!("invalid key-check nonce: {err}")))?;
    let ciphertext = hex::decode(&config.key_check_ciphertext_hex)
        .map_err(|err| ArgosError::Invalid(format!("invalid key-check ciphertext: {err}")))?;
    let marker = decrypt_with_key(&key, &nonce, &ciphertext, aad)?;
    if marker != b"argosfs-key-check" {
        return Err(ArgosError::PermissionDenied(
            "invalid ArgosFS encryption key".to_string(),
        ));
    }
    Ok(key)
}

pub fn encrypt_with_key(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ArgosError::Invalid("encryption failed".to_string()))?;
    Ok((nonce, ciphertext))
}

pub fn decrypt_with_key(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(ArgosError::Invalid(
            "invalid encryption nonce length".to_string(),
        ));
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ArgosError::PermissionDenied("decryption failed".to_string()))
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|err| ArgosError::Invalid(format!("invalid argon2 params: {err}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|err| ArgosError::Invalid(format!("key derivation failed: {err}")))?;
    let mut hasher = Sha256::new();
    hasher.update(out);
    hasher.update(b"argosfs-encryption-v1");
    out.copy_from_slice(&hasher.finalize()[..32]);
    Ok(out)
}
