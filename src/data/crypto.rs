use crate::error::{ArgosError, Result};
use crate::types::EncryptionConfig;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
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
    let salt: [u8; SALT_LEN] = rand::random();
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
    let nonce: [u8; NONCE_LEN] = rand::random();
    let cipher = XChaCha20Poly1305::new(
        <&Key>::try_from(&key[..])
            .map_err(|_| ArgosError::Invalid("invalid encryption key length".to_string()))?,
    );
    let ciphertext = cipher
        .encrypt(
            <&XNonce>::try_from(&nonce[..])
                .map_err(|_| ArgosError::Invalid("invalid encryption nonce length".to_string()))?,
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
    let cipher = XChaCha20Poly1305::new(
        <&Key>::try_from(&key[..])
            .map_err(|_| ArgosError::Invalid("invalid encryption key length".to_string()))?,
    );
    cipher
        .decrypt(
            <&XNonce>::try_from(nonce)
                .map_err(|_| ArgosError::Invalid("invalid encryption nonce length".to_string()))?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use tempfile::NamedTempFile;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn passphrase_prefers_key_file_and_trims_only_line_endings() {
        let _guard = env_lock();
        let mut file = NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b" file key  \r\n").unwrap();
        std::env::set_var("ARGOSFS_KEY", "environment key");
        std::env::set_var("ARGOSFS_KEY_FILE", file.path());
        assert_eq!(
            passphrase_from_env().unwrap(),
            Some(" file key  ".to_string())
        );
        std::env::remove_var("ARGOSFS_KEY_FILE");
        assert_eq!(
            passphrase_from_env().unwrap(),
            Some("environment key".to_string())
        );
        std::env::remove_var("ARGOSFS_KEY");
        assert_eq!(passphrase_from_env().unwrap(), None);
    }

    #[test]
    fn encryption_config_validates_key_aad_and_metadata() {
        let aad = b"volume-uuid";
        let config = new_encryption_config("correct horse", aad).unwrap();
        assert!(config.enabled);
        assert_eq!(config.kdf, "argon2id");
        assert_eq!(hex::decode(&config.salt_hex).unwrap().len(), SALT_LEN);
        assert_eq!(
            derive_key_for_config(&config, "correct horse", aad)
                .unwrap()
                .len(),
            32
        );
        assert!(matches!(
            derive_key_for_config(&config, "wrong horse", aad),
            Err(ArgosError::PermissionDenied(_))
        ));
        assert!(matches!(
            derive_key_for_config(&config, "correct horse", b"wrong aad"),
            Err(ArgosError::PermissionDenied(_))
        ));

        let mut invalid = config.clone();
        invalid.kdf = "scrypt".to_string();
        assert!(matches!(
            derive_key_for_config(&invalid, "correct horse", aad),
            Err(ArgosError::Invalid(_))
        ));
        invalid = config.clone();
        invalid.salt_hex = "zz".to_string();
        assert!(matches!(
            derive_key_for_config(&invalid, "correct horse", aad),
            Err(ArgosError::Invalid(_))
        ));
        invalid = config.clone();
        invalid.salt_hex = "00".to_string();
        assert!(matches!(
            derive_key_for_config(&invalid, "correct horse", aad),
            Err(ArgosError::Invalid(_))
        ));
        invalid = config.clone();
        invalid.key_check_nonce_hex = "zz".to_string();
        assert!(matches!(
            derive_key_for_config(&invalid, "correct horse", aad),
            Err(ArgosError::Invalid(_))
        ));
        invalid = config.clone();
        invalid.key_check_ciphertext_hex = "zz".to_string();
        assert!(matches!(
            derive_key_for_config(&invalid, "correct horse", aad),
            Err(ArgosError::Invalid(_))
        ));
    }

    #[test]
    fn authenticated_encryption_rejects_bad_nonce_ciphertext_and_aad() {
        let key = [7u8; 32];
        let plaintext = b"secret payload";
        let aad = b"metadata";
        let (nonce, ciphertext) = encrypt_with_key(&key, plaintext, aad).unwrap();
        assert_eq!(
            decrypt_with_key(&key, &nonce, &ciphertext, aad).unwrap(),
            plaintext
        );
        assert!(matches!(
            decrypt_with_key(&key, &nonce[..NONCE_LEN - 1], &ciphertext, aad),
            Err(ArgosError::Invalid(_))
        ));
        assert!(matches!(
            decrypt_with_key(&key, &nonce, &ciphertext, b"wrong"),
            Err(ArgosError::PermissionDenied(_))
        ));
        let mut damaged = ciphertext.clone();
        damaged[0] ^= 1;
        assert!(matches!(
            decrypt_with_key(&key, &nonce, &damaged, aad),
            Err(ArgosError::PermissionDenied(_))
        ));
    }
}
