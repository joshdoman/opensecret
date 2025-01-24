use bip39::Mnemonic;
use bitcoin::{
    bip32::{DerivationPath, Xpriv},
    Network,
};
use secp256k1::SecretKey;
use std::{str::FromStr, sync::Arc};

use crate::{
    aws_credentials::AwsCredentialManager,
    encrypt::{decrypt_with_key, generate_random_enclave},
    Error,
};

pub async fn generate_twelve_word_seed(
    aws_credential_manager: Arc<tokio::sync::RwLock<Option<AwsCredentialManager>>>,
) -> Result<Mnemonic, Error> {
    // the bip39 library supports 12. 15, 18, 21, and 24 word mnemonics
    // we only support 12 words, which is 16 bytes of entropy
    let random_bytes: [u8; 16] = generate_random_enclave::<16>(aws_credential_manager).await;

    let mnemonic =
        Mnemonic::from_entropy(&random_bytes).map_err(|_| Error::PrivateKeyGenerationFailure)?;
    Ok(mnemonic)
}

pub fn decrypt_user_seed_to_key(
    enclave_key: Vec<u8>,
    encrypted_seed: Vec<u8>,
    derivation_path: Option<&str>,
) -> Result<SecretKey, Error> {
    let user_mnemonic = decrypt_user_seed_to_mnemonic(enclave_key, encrypted_seed)?;
    let user_seed = user_mnemonic.to_seed("");
    let xprivkey = Xpriv::new_master(Network::Bitcoin, &user_seed)
        .map_err(|e| Error::EncryptionError(e.to_string()))?;

    // If a derivation path is provided, derive the child key
    if let Some(path) = derivation_path {
        let path = DerivationPath::from_str(path)
            .map_err(|e| Error::InvalidDerivationPath(e.to_string()))?;
        let derived_key = xprivkey
            .derive_priv(&secp256k1::Secp256k1::new(), &path)
            .map_err(|e| Error::KeyDerivationError(e.to_string()))?;
        Ok(derived_key.private_key)
    } else {
        Ok(xprivkey.private_key)
    }
}

pub fn decrypt_user_seed_to_mnemonic(
    enclave_key: Vec<u8>,
    encrypted_seed: Vec<u8>,
) -> Result<Mnemonic, Error> {
    let enclave_secret_key =
        SecretKey::from_slice(&enclave_key).map_err(|e| Error::EncryptionError(e.to_string()))?;
    let decrypted_user_seed_bytes = decrypt_with_key(&enclave_secret_key, &encrypted_seed)
        .map_err(|e| Error::EncryptionError(e.to_string()))?;
    let decrypted_user_seed_str = String::from_utf8(decrypted_user_seed_bytes)
        .map_err(|e| Error::EncryptionError(format!("Failed to decode UTF-8: {}", e)))?;
    let user_mnemonic = Mnemonic::from_str(&decrypted_user_seed_str)
        .map_err(|e| Error::EncryptionError(e.to_string()))?;
    Ok(user_mnemonic)
}
