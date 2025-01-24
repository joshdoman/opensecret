use crate::encrypt;
use crate::jwt::{NewToken, TokenType};
use crate::message_signing::SigningAlgorithm;
use crate::private_key::decrypt_user_seed_to_mnemonic;
use crate::web::encryption_middleware::{decrypt_request, encrypt_response, EncryptedResponse};
use crate::web::login_routes::handle_new_user_registration;
use crate::Credentials;
use crate::Error;
use crate::KVPair;
use crate::{
    db::DBError, email::send_verification_email, models::email_verification::NewEmailVerification,
    models::users::User, ApiError, AppState,
};
use axum::middleware::from_fn_with_state;
use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Router,
};
use axum::{Extension, Json};
use base64::{engine::general_purpose, Engine};
use bitcoin::bip32::DerivationPath;
use chrono::{DateTime, Utc};
use secp256k1::Secp256k1;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoginMethod {
    Email,
    Github,
    Google,
    Guest,
}

// Update AppUser struct to include login_method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUser {
    pub id: Uuid,
    pub name: Option<String>,
    pub email: Option<String>,
    pub email_verified: bool,
    pub login_method: LoginMethod,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&User> for AppUser {
    fn from(user: &User) -> Self {
        AppUser {
            id: user.uuid,
            name: user.name.clone(),
            email: user.email.clone(),
            // This will be set separately
            email_verified: false,
            // This will be updated for oauth
            login_method: if user.is_guest() {
                LoginMethod::Guest
            } else {
                LoginMethod::Email
            },
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[derive(Serialize)]
pub struct ProtectedUserData {
    pub user: AppUser,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct PrivateKeyResponse {
    mnemonic: String,
}

/// Response struct for the private key bytes endpoint.
/// Contains the private key encoded as a hexadecimal string.
#[derive(Debug, Serialize)]
pub struct PrivateKeyBytesResponse {
    /// The private key as a 64-character hexadecimal string (32 bytes).
    /// This is the standard secp256k1 private key format.
    private_key: String,
}

/// Query parameters for endpoints that accept a derivation path.
/// The derivation path should follow BIP32 format (e.g., "m/44'/0'/0'/0/0").
#[derive(Debug, Clone, Deserialize)]
pub struct DerivationPathQuery {
    derivation_path: Option<String>,
}

impl DerivationPathQuery {
    /// Validates that the derivation path follows BIP32 format if present.
    /// Both absolute (starting with "m/") and relative paths are valid.
    pub fn validate(&self) -> Result<(), ApiError> {
        if let Some(ref path) = self.derivation_path {
            // Allow empty path or "m" alone
            if path.is_empty() || path == "m" {
                return Ok(());
            }

            // For non-empty paths, validate using bitcoin library's DerivationPath
            DerivationPath::from_str(path).map_err(|e| {
                error!("Invalid derivation path format: {}", e);
                ApiError::BadRequest
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignMessageRequest {
    pub message_base64: String,
    pub algorithm: SigningAlgorithm,
    pub derivation_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignMessageResponseJson {
    pub signature: String,
    pub message_hash: String,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyResponseJson {
    pub public_key: String,
    pub algorithm: SigningAlgorithm,
}

#[derive(Debug, Deserialize)]
pub struct PublicKeyQuery {
    algorithm: SigningAlgorithm,
    derivation_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConvertGuestRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ThirdPartyTokenRequest {
    pub audience: String,
}

#[derive(Debug, Serialize)]
pub struct ThirdPartyTokenResponse {
    pub token: String,
}

pub fn router(app_state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route(
            "/protected/user",
            get(user_protected).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/protected/kv/:key",
            get(get_kv).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/protected/kv/:key",
            put(put_kv).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<String>,
            )),
        )
        .route(
            "/protected/kv/:key",
            delete(delete_kv).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/protected/kv",
            get(list_kv).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/protected/request_verification",
            post(request_new_verification_code)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/protected/change_password",
            post(change_password).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<ChangePasswordRequest>,
            )),
        )
        .route(
            "/protected/private_key",
            get(get_private_key)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/protected/private_key_bytes",
            get(get_private_key_bytes).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<DerivationPathQuery>,
            )),
        )
        .route(
            "/protected/sign_message",
            post(sign_message).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<SignMessageRequest>,
            )),
        )
        .route(
            "/protected/public_key",
            get(get_public_key).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/protected/convert_guest",
            post(convert_guest_to_email).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<ConvertGuestRequest>,
            )),
        )
        .route(
            "/protected/third_party_token",
            post(generate_third_party_token).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<ThirdPartyTokenRequest>,
            )),
        )
        .with_state(app_state.clone())
}

pub async fn user_protected(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<ProtectedUserData>>, ApiError> {
    debug!("Entering user_protected function");
    tracing::info!("user_protected request");
    let mut app_user: AppUser = AppUser::from(&user);

    // Set email verification status - only if not a guest user
    app_user.email_verified = if user.is_guest() {
        false
    } else {
        match data.db.get_email_verification_by_user_id(user.uuid) {
            Ok(verification) => verification.is_verified,
            Err(DBError::EmailVerificationNotFound) => false,
            Err(e) => {
                tracing::error!("Error checking email verification: {:?}", e);
                return Err(ApiError::InternalServerError);
            }
        }
    };

    // Determine login method
    if user.password_enc.is_none() {
        // This is an OAuth user - find out which provider
        match data.db.get_all_user_oauth_connections_for_user(user.uuid) {
            Ok(connections) => {
                if let Some(connection) = connections.first() {
                    // Get the provider details
                    match data.db.get_oauth_provider_by_id(connection.provider_id) {
                        Ok(Some(provider)) => {
                            // Set the login method based on the provider name
                            app_user.login_method = match provider.name.as_str() {
                                "github" => LoginMethod::Github,
                                "google" => LoginMethod::Google,
                                // Add other providers here as they're supported
                                _ => {
                                    tracing::error!("Unknown OAuth provider: {}", provider.name);
                                    return Err(ApiError::InternalServerError);
                                }
                            };
                        }
                        Ok(None) => {
                            tracing::error!(
                                "OAuth provider not found for id: {}",
                                connection.provider_id
                            );
                            return Err(ApiError::InternalServerError);
                        }
                        Err(e) => {
                            tracing::error!("Error fetching OAuth provider: {:?}", e);
                            return Err(ApiError::InternalServerError);
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Error fetching OAuth connections: {:?}", e);
                return Err(ApiError::InternalServerError);
            }
        }
    }

    let response = ProtectedUserData { user: app_user };

    debug!("Exiting user_protected function");
    encrypt_response(&data, &session_id, &response).await
}

pub async fn get_kv(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(session_id): Extension<Uuid>,
    Path(key): Path<String>,
) -> Result<Json<EncryptedResponse<Option<String>>>, ApiError> {
    debug!("Entering get_kv function");
    let value = match data.get(user.uuid, key).await {
        Ok(kv) => kv,
        Err(e) => {
            tracing::error!("Error getting key-value pair: {:?}", e);
            return Err(ApiError::InternalServerError);
        }
    };
    debug!("Exiting get_kv function");
    encrypt_response(&data, &session_id, &value).await
}

pub async fn put_kv(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(session_id): Extension<Uuid>,
    Path(key): Path<String>,
    Extension(value): Extension<String>,
) -> Result<Json<EncryptedResponse<String>>, ApiError> {
    debug!("Entering put_kv function");
    info!("Putting key-value pair for user");
    tracing::trace!("putting key-value pair: {} = {}", key, value);

    match data.put(user.uuid, key, value.clone()).await {
        Ok(kv) => kv,
        Err(e) => {
            tracing::error!("Error putting key-value pair: {:?}", e);
            return Err(ApiError::InternalServerError);
        }
    };

    debug!("Exiting put_kv function");
    encrypt_response(&data, &session_id, &value).await
}

pub async fn delete_kv(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(session_id): Extension<Uuid>,
    Path(key): Path<String>,
) -> Result<Json<EncryptedResponse<serde_json::Value>>, ApiError> {
    debug!("Entering delete_kv function");
    match data.delete(user.uuid, key).await {
        Ok(_) => {
            let response = json!({ "message": "Resource deleted successfully" });
            debug!("Exiting delete_kv function");
            encrypt_response(&data, &session_id, &response).await
        }
        Err(e) => {
            tracing::error!("Error deleting key-value pair: {:?}", e);
            Err(ApiError::InternalServerError)
        }
    }
}

pub async fn list_kv(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<Vec<KVPair>>>, ApiError> {
    debug!("Entering list_kv function");
    let kvs = match data.list(user.uuid).await {
        Ok(kvs) => kvs,
        Err(e) => {
            tracing::error!("Error listing key-value pairs: {:?}", e);
            return Err(ApiError::InternalServerError);
        }
    };
    debug!("Exiting list_kv function");
    encrypt_response(&data, &session_id, &kvs).await
}

pub async fn request_new_verification_code(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<serde_json::Value>>, ApiError> {
    debug!("Entering request_new_verification_code function");

    // First check if user has an email
    let email = match user.get_email() {
        Some(email) => email.to_string(),
        None => {
            let response = json!({ "error": "No email associated with account" });
            return encrypt_response(&data, &session_id, &response).await;
        }
    };

    // Check if the user is already verified
    match data.db.get_email_verification_by_user_id(user.uuid) {
        Ok(verification) => {
            if verification.is_verified {
                let response = json!({ "error": "User is already verified" });
                return encrypt_response(&data, &session_id, &response).await;
            }
            // Delete the old verification
            if let Err(e) = data.db.delete_email_verification(&verification) {
                tracing::error!("Error deleting old verification: {:?}", e);
                return Err(ApiError::InternalServerError);
            }
        }
        Err(DBError::EmailVerificationNotFound) => {
            // This is fine, we'll create a new verification
        }
        Err(e) => {
            tracing::error!("Error checking email verification: {:?}", e);
            return Err(ApiError::InternalServerError);
        }
    }

    // Create a new verification entry
    let new_verification = NewEmailVerification::new(user.uuid, 24, false); // 24 hours expiration
    let verification = match data.db.create_email_verification(new_verification) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Error creating email verification: {:?}", e);
            return Err(ApiError::InternalServerError);
        }
    };

    // Send the new verification email
    if let Err(e) = send_verification_email(
        data.app_mode.clone(),
        data.resend_api_key.clone(),
        email,
        verification.verification_code,
    )
    .await
    {
        tracing::error!("Error sending verification email: {:?}", e);
        return Err(ApiError::InternalServerError);
    }

    let response = json!({ "message": "New verification code sent successfully" });
    debug!("Exiting request_new_verification_code function");
    encrypt_response(&data, &session_id, &response).await
}

pub async fn change_password(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(change_request): Extension<ChangePasswordRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<serde_json::Value>>, ApiError> {
    debug!("Entering change_password function");

    // Check if user is an OAuth-only user
    if user.password_enc.is_none() {
        error!("OAuth-only user attempted to change password");
        return Err(ApiError::InvalidUsernameOrPassword);
    }

    // Get email if it exists
    let email = user.get_email().map(|e| e.to_string());

    // Verify the current password
    let credentials = Credentials {
        email,
        id: Some(user.uuid),
        password: change_request.current_password,
    };

    match data.authenticate_user(credentials).await {
        Ok(Some(authenticated_user)) if authenticated_user.uuid == user.uuid => {
            // Current password is correct, proceed with password change
            match data
                .update_user_password(&user, change_request.new_password)
                .await
            {
                Ok(()) => {
                    let response = json!({ "message": "Password changed successfully" });
                    debug!("Exiting change_password function");
                    encrypt_response(&data, &session_id, &response).await
                }
                Err(e) => {
                    error!("Error changing password: {:?}", e);
                    Err(ApiError::InternalServerError)
                }
            }
        }
        _ => {
            // Current password is incorrect
            Err(ApiError::InvalidUsernameOrPassword)
        }
    }
}

pub async fn get_private_key(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<PrivateKeyResponse>>, ApiError> {
    debug!("Entering get_private_key function");

    // First try to get the existing encrypted seed
    let encrypted_seed = match user.get_seed_encrypted().await {
        Some(seed) => seed,
        None => {
            // Only generate a new key if one doesn't exist
            debug!("No existing key found, generating new key");
            data.generate_private_key(user.uuid)
                .await
                .map_err(|e| {
                    error!("Failed to generate private key: {:?}", e);
                    ApiError::InternalServerError
                })?
                .get_seed_encrypted()
                .await
                .ok_or_else(|| {
                    error!("Private key not found after generation: {}", user.uuid);
                    ApiError::InternalServerError
                })?
        }
    };

    // Decrypt the seed to get the mnemonic
    let mnemonic = decrypt_user_seed_to_mnemonic(data.enclave_key.clone(), encrypted_seed)
        .map_err(|e| {
            error!("Failed to decrypt user seed: {:?}", e);
            ApiError::InternalServerError
        })?;

    let response = PrivateKeyResponse {
        mnemonic: mnemonic.to_string(),
    };

    debug!("Exiting get_private_key function");
    encrypt_response(&data, &session_id, &response).await
}

pub async fn get_private_key_bytes(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(session_id): Extension<Uuid>,
    Query(query): Query<DerivationPathQuery>,
) -> Result<Json<EncryptedResponse<PrivateKeyBytesResponse>>, ApiError> {
    debug!("Entering get_private_key_bytes function");

    // Validate derivation path if present
    query.validate()?;

    let secret_key = data
        .get_user_key(user.uuid, query.derivation_path.as_deref())
        .await
        .map_err(|e| match e {
            Error::InvalidDerivationPath(msg) => {
                error!("Invalid derivation path: {}", msg);
                ApiError::BadRequest
            }
            Error::KeyDerivationError(msg) => {
                error!("Failed to derive key: {}", msg);
                ApiError::BadRequest
            }
            _ => {
                error!("Failed to get user key: {:?}", e);
                ApiError::InternalServerError
            }
        })?;

    let response = PrivateKeyBytesResponse {
        private_key: secret_key.display_secret().to_string(),
    };

    debug!("Exiting get_private_key_bytes function");
    encrypt_response(&data, &session_id, &response).await
}

pub async fn sign_message(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(sign_request): Extension<SignMessageRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<SignMessageResponseJson>>, ApiError> {
    debug!("Entering sign_message function");

    let message_bytes = general_purpose::STANDARD
        .decode(&sign_request.message_base64)
        .map_err(|e| {
            error!("Failed to decode base64 message: {:?}", e);
            ApiError::BadRequest
        })?;

    let response = data
        .sign_message(
            user.uuid,
            &message_bytes,
            sign_request.algorithm,
            sign_request.derivation_path.as_deref(),
        )
        .await
        .map_err(|e| {
            error!("Error signing message: {:?}", e);
            ApiError::InternalServerError
        })?;

    let json_response = SignMessageResponseJson {
        signature: response.signature.to_string(),
        message_hash: hex::encode(response.message_hash),
    };

    debug!("Exiting sign_message function");
    encrypt_response(&data, &session_id, &json_response).await
}

pub async fn get_public_key(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(session_id): Extension<Uuid>,
    Query(query): Query<PublicKeyQuery>,
) -> Result<Json<EncryptedResponse<PublicKeyResponseJson>>, ApiError> {
    debug!("Entering get_public_key function");

    let user_secret_key = data
        .get_user_key(user.uuid, query.derivation_path.as_deref())
        .await
        .map_err(|e| {
            error!("Error getting user key: {:?}", e);
            ApiError::InternalServerError
        })?;

    let secp = Secp256k1::new();
    let public_key = user_secret_key.public_key(&secp);

    // Format public key according to algorithm
    let public_key_str = match query.algorithm {
        SigningAlgorithm::Schnorr => {
            let (xonly_pubkey, _parity) = public_key.x_only_public_key();
            xonly_pubkey.to_string()
        }
        SigningAlgorithm::Ecdsa => {
            // For ECDSA, use the compressed format
            public_key.to_string()
        }
    };

    let response = PublicKeyResponseJson {
        public_key: public_key_str,
        algorithm: query.algorithm,
    };

    debug!("Exiting get_public_key function");
    encrypt_response(&data, &session_id, &response).await
}

pub async fn convert_guest_to_email(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(convert_request): Extension<ConvertGuestRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<serde_json::Value>>, ApiError> {
    debug!("Entering convert_guest_to_email function");

    // Check if user is eligible for conversion
    if !user.is_guest() {
        error!("User already has an email address");
        return Err(ApiError::BadRequest);
    }

    if user.password_enc.is_none() {
        error!("OAuth users cannot be converted");
        return Err(ApiError::BadRequest);
    }

    // Check if email is already taken
    if data
        .db
        .get_user_by_email(convert_request.email.clone())
        .is_ok()
    {
        error!("Email address already in use");
        return Err(ApiError::EmailAlreadyExists);
    }

    // Hash and encrypt the new password
    let password_hash = password_auth::generate_hash(convert_request.password);
    let secret_key =
        SecretKey::from_slice(&data.enclave_key).map_err(|_| ApiError::InternalServerError)?;
    let encrypted_password = encrypt::encrypt_with_key(&secret_key, password_hash.as_bytes()).await;

    // Update the user with new email, password, and optional name
    let mut updated_user = user.clone();
    updated_user.email = Some(convert_request.email);
    updated_user.password_enc = Some(encrypted_password);
    updated_user.name = convert_request.name;

    // Save the changes
    if let Err(e) = data.db.update_user(&updated_user) {
        error!("Failed to update user: {:?}", e);
        return Err(ApiError::InternalServerError);
    }

    // Handle email verification and welcome emails
    if let Err(e) = handle_new_user_registration(&data, &updated_user, true).await {
        error!("Failed to handle registration tasks: {:?}", e);
        return Err(e);
    }

    let response = json!({
        "message": "Successfully converted guest account to email account. Please check your email for verification."
    });

    debug!("Exiting convert_guest_to_email function");
    encrypt_response(&data, &session_id, &response).await
}

pub async fn generate_third_party_token(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Extension(request): Extension<ThirdPartyTokenRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<ThirdPartyTokenResponse>>, ApiError> {
    debug!("Entering generate_third_party_token function");
    info!(
        "Generating third party token for user {} with audience {}",
        user.uuid, request.audience
    );

    // Validate the audience URL
    if url::Url::parse(&request.audience).is_err() {
        error!("Invalid audience URL provided: {}", request.audience);
        return Err(ApiError::BadRequest);
    }

    debug!("Audience URL validation successful");

    let token = match NewToken::new(
        &user,
        TokenType::ThirdParty {
            aud: request.audience.clone(),
            azp: "maple".to_string(),
        },
        &data,
    ) {
        Ok(token) => {
            info!(
                "Successfully generated third party token for user {}",
                user.uuid
            );
            token
        }
        Err(e) => {
            error!("Failed to generate third party token: {:?}", e);
            return Err(e);
        }
    };

    let response = ThirdPartyTokenResponse { token: token.token };

    debug!("Exiting generate_third_party_token function");
    encrypt_response(&data, &session_id, &response).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation_path_validation() {
        // Test valid paths
        let valid_paths = vec![
            "m/44'/0'/0'/0/0", // Standard BIP44 absolute
            "44'/0'/0'/0/0",   // Standard BIP44 relative
            "m/84'/0'/0'/0/0", // Standard BIP84 absolute
            "84'/0'/0'/0/0",   // Standard BIP84 relative
            "m/49'/0'/0'/0/0", // Standard BIP49 absolute
            "0/0",             // Simple relative path
            "m/0/0",           // Simple absolute path
            "0",               // Single level relative
            "m/0",             // Single level absolute
            "m",               // Master key
            "",                // Empty path
            "0'",              // Hardened child
            "m/0'",            // Hardened child absolute
            "0h",              // Hardened child (alternate notation)
            "m/0h",            // Hardened child absolute (alternate notation)
        ];

        for path in valid_paths {
            let query = DerivationPathQuery {
                derivation_path: Some(path.to_string()),
            };
            assert!(query.validate().is_ok(), "Path should be valid: {}", path);
        }

        // Test invalid paths
        let invalid_paths = vec![
            "invalid",      // Random string
            "m//0",         // Double slash
            "m/x/0",        // Invalid character
            "m/0'/x/0",     // Invalid character after hardened
            "M/0/0",        // Wrong case for master key
            "m/2147483648", // Exceeds u32::MAX
            "n/0/0",        // Wrong master key letter
            "/0/0",         // Slash without master key
        ];

        for path in invalid_paths {
            let query = DerivationPathQuery {
                derivation_path: Some(path.to_string()),
            };
            assert!(
                query.validate().is_err(),
                "Path should be invalid: {}",
                path
            );
        }

        // Test None path
        let query = DerivationPathQuery {
            derivation_path: None,
        };
        assert!(query.validate().is_ok(), "None path should be valid");
    }
}
