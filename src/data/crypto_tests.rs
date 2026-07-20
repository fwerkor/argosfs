use super::*;
use tempfile::NamedTempFile;

#[test]
fn passphrase_prefers_key_file_and_trims_only_line_endings() {
    let _guard = test_env_lock();
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
