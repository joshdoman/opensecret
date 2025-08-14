use crate::encrypt::encrypt_key_deterministic;
use crate::encrypt::generate_random;
use crate::encrypt::{
    decrypt_with_key, decrypt_with_kms, encrypt_with_key, CustomRng, GenKeyResult,
};
use crate::web::{
    health_routes_with_state,
};
use crate::{attestation_routes::SessionState};

use crate::{
    aws_credentials::AwsCredentialError,
    private_key::{decrypt_user_seed_to_key, generate_twelve_word_seed},
};
use crate::{encrypt::create_new_encryption_key};
use aws_credentials::{AwsCredentialManager, AwsCredentials};
use axum::{http::StatusCode, middleware::from_fn_with_state, response::IntoResponse, Json};
use base64::engine::general_purpose;
use base64::Engine as _;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{CryptoRng, RngCore};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::spawn;
use tokio::sync::RwLock;
use tokio::task::{self};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use url::Url;
use uuid::Uuid;
use vsock::{VsockAddr, VsockStream};
use web::attestation_routes;
use x25519_dalek::{EphemeralSecret, PublicKey};

mod aws_credentials;
mod encrypt;
mod jwt;
mod message_signing;
mod private_key;
mod web;

const ENCLAVE_KEY_NAME: &str = "enclave_key";
const JWT_SECRET_KEY_NAME: &str = "jwt_secret";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnclaveRequest {
    pub request_type: String,
    pub key_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ParentResponse {
    pub response_type: String,
    pub response_value: serde_json::Value,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    TaskJoin(#[from] task::JoinError),

    #[error(transparent)]
    StdIo(#[from] std::io::Error),

    #[error(transparent)]
    TryInit(#[from] tracing_subscriber::util::TryInitError),

    #[error("Private key not found")]
    PrivateKeyNotFound,

    #[error("Private key could not be generated")]
    PrivateKeyGenerationFailure,

    #[error("Private key already exists")]
    PrivateKeyAlreadyExists,

    #[error("User not found")]
    UserNotFound,

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Authentication error")]
    AuthenticationError,

    #[error("Failed to parse secret")]
    SecretParsingError,

    #[error("AWS Credential error: {0}")]
    AwsCredentialError(#[from] aws_credentials::AwsCredentialError),

    #[error("User is already verified")]
    UserAlreadyVerified,

    #[error("Builder error: {0}")]
    BuilderError(String),

    #[error("Password reset request expired")]
    PasswordResetExpired,

    #[error("Invalid password reset secret")]
    InvalidPasswordResetSecret,

    #[error("Invalid password reset request")]
    InvalidPasswordResetRequest,

    #[error("Account deletion request expired")]
    AccountDeletionExpired,

    #[error("Invalid account deletion secret")]
    InvalidAccountDeletionSecret,

    #[error("Invalid account deletion request")]
    InvalidAccountDeletionRequest,

    #[error("Password is required for registration")]
    PasswordRequired,

    #[error("OAuth error: {0}")]
    OAuthError(String),

    #[error("User with this email already exists")]
    UserAlreadyExists,

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Invalid JWT")]
    InvalidJwt,

    #[error("Internal server error")]
    InternalServerError,

    #[error("Bad Request")]
    BadRequest,

    #[error("Encryption error")]
    EncryptionError,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Token refresh failed")]
    RefreshFailed,

    #[error("Resource not found")]
    NotFound,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            ApiError::InvalidJwt => StatusCode::UNAUTHORIZED,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::BadRequest => StatusCode::BAD_REQUEST,
            ApiError::RefreshFailed => StatusCode::UNAUTHORIZED,
            ApiError::EncryptionError => StatusCode::BAD_REQUEST,
            ApiError::NotFound => StatusCode::NOT_FOUND,
        };
        (
            status,
            Json(ErrorResponse {
                status: status.as_u16(),
                message: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    status: u16,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    // Subject (whom token refers to)
    pub sub: String, // This will now be the UUID
    // Expiration time (as UTC timestamp)
    pub exp: i64,
    // Issued at (as UTC timestamp)
    pub iat: i64,
    // Audience
    pub aud: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    jwt_keys: jwt::JwtKeys,
    access_token_maxage: i64,
    refresh_token_maxage: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppMode {
    Local,
    Dev,
    Preview,
    Prod,
    Custom(String),
}

impl AppMode {
    fn frontend_url(&self) -> &str {
        match self {
            AppMode::Local => "http://127.0.0.1:5173",
            AppMode::Dev => "https://dev.secretgpt.ai",
            AppMode::Preview => "https://preview.opensecret.cloud",
            AppMode::Prod => "https://trymaple.ai",
            AppMode::Custom(_) => "https://preview.opensecret.cloud",
        }
    }
}

impl fmt::Display for AppMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AppMode::Local => write!(f, "local"),
            AppMode::Dev => write!(f, "dev"),
            AppMode::Preview => write!(f, "preview"),
            AppMode::Prod => write!(f, "prod"),
            AppMode::Custom(_) => write!(f, "custom"),
        }
    }
}

impl FromStr for AppMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local" => Ok(AppMode::Local),
            "dev" => Ok(AppMode::Dev),
            "preview" => Ok(AppMode::Preview),
            "prod" => Ok(AppMode::Prod),
            "custom" => {
                // For custom mode, get the ENV_NAME
                match std::env::var("ENV_NAME") {
                    Ok(env_name) => Ok(AppMode::Custom(env_name)),
                    Err(_) => Err("ENV_NAME must be set when using custom mode".to_string()),
                }
            }
            _ => Err(format!("Invalid app mode: {}", s)),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    app_mode: AppMode,
    config: Config,
    aws_credential_manager: Arc<tokio::sync::RwLock<Option<AwsCredentialManager>>>,
    enclave_key: Vec<u8>,
    ephemeral_keys: Arc<RwLock<HashMap<String, EphemeralSecret>>>,
}

#[derive(Default)]
pub struct AppStateBuilder {
    app_mode: Option<AppMode>,
    enclave_key: Option<Vec<u8>>,
    aws_credential_manager: Option<Arc<tokio::sync::RwLock<Option<AwsCredentialManager>>>>,
    jwt_secret: Option<Vec<u8>>,
}

impl AppStateBuilder {
    pub fn app_mode(mut self, app_mode: AppMode) -> Self {
        self.app_mode = Some(app_mode);
        self
    }

    pub fn enclave_key(mut self, enclave_key: Vec<u8>) -> Self {
        self.enclave_key = Some(enclave_key);
        self
    }

    pub fn aws_credential_manager(
        mut self,
        aws_credential_manager: Arc<tokio::sync::RwLock<Option<AwsCredentialManager>>>,
    ) -> Self {
        self.aws_credential_manager = Some(aws_credential_manager);
        self
    }

    pub fn jwt_secret(mut self, jwt_secret: Vec<u8>) -> Self {
        self.jwt_secret = Some(jwt_secret);
        self
    }

    pub async fn build(self) -> Result<AppState, Error> {
        let app_mode = self
            .app_mode
            .ok_or(Error::BuilderError("app_mode is required".to_string()))?;
        let enclave_key = self
            .enclave_key
            .ok_or(Error::BuilderError("enclave_key is required".to_string()))?;
        let aws_credential_manager = self.aws_credential_manager.ok_or(Error::BuilderError(
            "aws_credential_manager is required".to_string(),
        ))?;
        let jwt_secret = self
            .jwt_secret
            .ok_or(Error::BuilderError("jwt_secret is required".to_string()))?;

        let config = Config {
            jwt_keys: jwt::JwtKeys::new(jwt_secret)?,
            access_token_maxage: 60,  // 60 minutes
            refresh_token_maxage: 30, // 30 days
        };

        // Log the public key in hex format
        tracing::info!(
            "JWT ES256K public key (hex): {}",
            hex::encode(config.jwt_keys.public_key().serialize())
        );

        Ok(AppState {
            app_mode,
            config,
            aws_credential_manager,
            enclave_key,
            ephemeral_keys: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

impl AppState {
    pub async fn get_aws_credentials(&self) -> Option<AwsCredentials> {
        if let Some(manager) = self.aws_credential_manager.read().await.as_ref() {
            manager.get_credentials().await
        } else {
            None
        }
    }

    pub async fn get_enclave_key(&self) -> Vec<u8> {
        self.enclave_key.clone()
    }

    pub async fn create_ephemeral_key(&self, nonce: String) -> PublicKey {
        let custom_rng = CustomRng::new();

        // Use a wrapper that implements RngCore and CryptoRng
        let mut rng_wrapper = AsyncRngWrapper::new(custom_rng);

        // Create the EphemeralSecret using the RngCore implementation
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut rng_wrapper);
        let public_key = PublicKey::from(&ephemeral_secret);

        self.ephemeral_keys
            .write()
            .await
            .insert(nonce, ephemeral_secret);

        public_key
    }

    pub async fn get_and_remove_ephemeral_secret(&self, nonce: &str) -> Option<EphemeralSecret> {
        self.ephemeral_keys.write().await.remove(nonce)
    }

    pub fn frontend_url(&self) -> String {
        self.app_mode.frontend_url().to_string()
    }
}

async fn get_secret(key_name: &str) -> Result<String, Error> {
    let cid = 3;
    let port = 8003;

    let sock_addr = VsockAddr::new(cid, port);
    let mut stream = VsockStream::connect(&sock_addr)?;

    let request = EnclaveRequest {
        request_type: "SecretsManager".to_string(),
        key_name: Some(key_name.to_string()),
    };
    let request_json = serde_json::to_string(&request)?;
    stream.write_all(request_json.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    let parent_response: ParentResponse = serde_json::from_str(&response)?;
    if parent_response.response_type == "secret" {
        let secret_json: Value =
            serde_json::from_str(parent_response.response_value.as_str().unwrap())?;

        // Assuming the secret is always a JSON object with a single key-value pair
        if let Some((_, value)) = secret_json.as_object().and_then(|obj| obj.iter().next()) {
            Ok(value.as_str().unwrap_or_default().to_string())
        } else {
            Err(Error::SecretParsingError)
        }
    } else {
        Err(Error::AuthenticationError)
    }
}

async fn get_or_create_enclave_key(
    app_mode: &AppMode,
    aws_credential_manager: Arc<tokio::sync::RwLock<Option<AwsCredentialManager>>>,
) -> Result<GenKeyResult, Error> {
    let creds = aws_credential_manager
        .read()
        .await
        .clone()
        .expect("non-local mode should have creds")
        .get_credentials()
        .await
        .expect("non-local mode should have creds");

    let aws_kms_key_id = get_kms_key_id(app_mode);

    // Create a new encryption key
    let key_res = create_new_encryption_key(
        &creds.region,
        &creds.access_key_id,
        &creds.secret_access_key,
        &creds.token,
        &aws_kms_key_id,
    )
    .map_err(|e| Error::EncryptionError(e.to_string()))?;

    // Store the encrypted version of the key if it's new
    // if existing_key.is_none() {
    //     let new_secret =
    //         NewEnclaveSecret::new(ENCLAVE_KEY_NAME.to_string(), key_res.encrypted_key.clone());
    //     db.create_enclave_secret(new_secret)?;
    // }

    Ok(key_res)
}

async fn get_or_create_jwt_secret(
    app_mode: &AppMode,
    aws_credential_manager: Arc<tokio::sync::RwLock<Option<AwsCredentialManager>>>,
    enclave_key: &[u8],
) -> Result<Vec<u8>, Error> {
    match app_mode {
        AppMode::Local => {
            // For local mode, use environment variable
            Ok(std::env::var("JWT_SECRET")
                .expect("JWT_SECRET must be set in local mode")
                .into_bytes())
        }
        _ => {
            // Generate new JWT secret
            let jwt_secret = jwt::generate_jwt_secret(aws_credential_manager.clone()).await?;

            // Encrypt and store the new JWT secret
            let secret_key = SecretKey::from_slice(enclave_key)
                .map_err(|e| Error::EncryptionError(e.to_string()))?;
            let encrypted_jwt_secret = encrypt_with_key(&secret_key, &jwt_secret).await;

            // let new_secret =
            //     NewEnclaveSecret::new(JWT_SECRET_KEY_NAME.to_string(), encrypted_jwt_secret);
            // db.create_enclave_secret(new_secret)?;

            Ok(jwt_secret)
        }
    }
}

fn get_kms_key_id(app_mode: &AppMode) -> String {
    match app_mode {
        AppMode::Prod => "alias/open-secret-prod-enclave".to_string(),
        AppMode::Preview => "alias/open-secret-preview1-enclave".to_string(),
        AppMode::Dev => "alias/open-secret-dev-enclave".to_string(),
        AppMode::Custom(env_name) => format!("alias/open-secret-{}-enclave", env_name),
        AppMode::Local => unreachable!("shouldn't use kms in local mode"),
    }
}

struct AsyncRngWrapper {
    inner: CustomRng,
}

impl AsyncRngWrapper {
    fn new(inner: CustomRng) -> Self {
        AsyncRngWrapper { inner }
    }
}

impl RngCore for AsyncRngWrapper {
    fn next_u32(&mut self) -> u32 {
        futures::executor::block_on(self.inner.next_u32())
    }

    fn next_u64(&mut self) -> u64 {
        futures::executor::block_on(self.inner.next_u64())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        futures::executor::block_on(self.inner.fill_bytes(dest))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        futures::executor::block_on(self.inner.fill_bytes(dest));
        Ok(())
    }
}

// Implement CryptoRng for AsyncRngWrapper
impl CryptoRng for AsyncRngWrapper {}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Add debug logs for entrypoints and exit points
    tracing::debug!("Starting application");

    // Load .env file
    dotenv::dotenv().ok();

    let app_mode = std::env::var("APP_MODE")
        .unwrap_or_else(|_| "local".to_string())
        .parse::<AppMode>()
        .expect("Invalid APP_MODE");

    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| {
                "sg_backend=debug,axum_login=debug,tower_sessions=debug,sqlx=warn,tower_http=debug"
                    .into()
            },
        )))
        .with(tracing_subscriber::fmt::layer().with_ansi(false))
        .try_init()?;

    let aws_credential_manager = if app_mode != AppMode::Local {
        Arc::new(RwLock::new(Some(AwsCredentialManager::new())))
    } else {
        Arc::new(RwLock::new(None))
    };

    if app_mode != AppMode::Local {
        // Wait for initial credentials with a timeout
        let timeout = Duration::from_secs(60); // 1 minute timeout
        match tokio::time::timeout(
            timeout,
            aws_credential_manager
                .read()
                .await
                .as_ref()
                .expect("non-local mode should have creds")
                .wait_for_credentials(),
        )
        .await
        {
            Ok(_) => tracing::info!("Initial AWS credentials fetched successfully"),
            Err(_) => {
                tracing::error!("Timed out waiting for initial AWS credentials");
                return Err(Error::AwsCredentialError(AwsCredentialError::Timeout));
            }
        }

        // Spawn a task to refresh AWS credentials
        let refresh_manager = aws_credential_manager.clone();
        tokio::spawn(async move {
            let refresh_interval = Duration::from_secs(5 * 60 * 60); // 5 hours
            let retry_interval = Duration::from_secs(5); // 5 seconds

            loop {
                tracing::info!("Refreshing AWS credentials");

                let fetch_res = refresh_manager
                    .read()
                    .await
                    .as_ref()
                    .expect("non-local mode should have creds")
                    .fetch_credentials()
                    .await;

                match fetch_res {
                    Ok(_creds) => {
                        tracing::info!("AWS credentials refreshed successfully");
                        tokio::time::sleep(refresh_interval).await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to refresh AWS credentials: {:?}", e);
                        tracing::info!("Retrying in 5 seconds...");
                        tokio::time::sleep(retry_interval).await;
                    }
                }
            }
        });
    }

    // enclave secret retrieval
    let enclave_key = if app_mode != AppMode::Local {
        let enclave_key =
            get_or_create_enclave_key(&app_mode, aws_credential_manager.clone())
                .await?;
        enclave_key.key
    } else {
        let enclave_key =
            std::env::var("ENCLAVE_SECRET_MOCK").expect("needs ENCLAVE_SECRET_MOCK in local mode");
        let enclave_key: [u8; 32] = hex::decode(enclave_key)
            .unwrap()
            .try_into()
            .expect("ENCLAVE_SECRET_MOCK must be 32 bytes");
        enclave_key.to_vec()
    };

    let jwt_secret = get_or_create_jwt_secret(
        &app_mode,
        aws_credential_manager.clone(),
        &enclave_key,
    )
    .await?;

    let app_state = AppStateBuilder::default()
        .app_mode(app_mode.clone())
        .enclave_key(enclave_key)
        .aws_credential_manager(aws_credential_manager)
        .jwt_secret(jwt_secret)
        .build()
        .await?;
    tracing::info!("App state created, app_mode: {:?}", app_mode);

    let app_state = Arc::new(app_state);

    let cors = CorsLayer::new()
        // allow all method types
        .allow_methods(Any)
        // allow all headers
        .allow_headers(Any)
        // allow requests from any origin
        .allow_origin(Any);

    let app = health_routes_with_state(app_state.clone())
        .merge(attestation_routes::router(app_state.clone()))
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    tracing::info!("Listening on http://localhost:3000");

    Ok(axum::serve(listener, app.into_make_service()).await?)
}
