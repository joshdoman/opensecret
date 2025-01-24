use crate::aws_credentials::AwsCredentialManager;
use crate::encrypt::generate_random_bytes_from_enclave;
use crate::Error;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::IntoResponse,
};
use chrono::Duration;
use jwt_compact::{alg::Es256k, prelude::*, AlgorithmExt};
use secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::AppMode;
use crate::{ApiError, AppState, User};
use url::Url;

pub enum TokenType {
    Access,
    Refresh,
    ThirdParty { aud: String, azp: String },
}

#[derive(Debug, Clone)]
pub struct NewToken {
    pub token: String,
}

#[derive(Debug, Clone)]
pub struct JwtKeys {
    pub(crate) legacy_secret: Vec<u8>, // For old HMAC tokens
    signing_key: SecretKey,            // For ES256K
    secp: Secp256k1<All>,
}

impl JwtKeys {
    pub fn new(secret_bytes: Vec<u8>) -> Result<Self, Error> {
        let secp = Secp256k1::new(); // Creates All context
        let signing_key = SecretKey::from_slice(&secret_bytes[..32])
            .map_err(|e| Error::EncryptionError(e.to_string()))?;

        Ok(Self {
            legacy_secret: secret_bytes,
            signing_key,
            secp,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(&self.secp, &self.signing_key)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct CustomClaims {
    pub sub: String,
    pub aud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
}

impl TokenType {
    pub fn validate_third_party_audience(aud: &str, app_mode: &AppMode) -> Result<(), ApiError> {
        // Parse the URL first
        let url = Url::parse(aud).map_err(|_| {
            tracing::error!("Invalid audience URL format: {}", aud);
            ApiError::BadRequest
        })?;

        // Allow localhost/127.0.0.1/0.0.0.0 in local mode
        if matches!(app_mode, AppMode::Local) {
            let host = url.host_str().unwrap_or_default();
            if host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" {
                return Ok(());
            }
        }

        // Define allowed production/staging domains
        const ALLOWED_DOMAINS: [&str; 2] =
            ["billing.opensecret.cloud", "billing-dev.opensecret.cloud"];

        if ALLOWED_DOMAINS.contains(&url.host_str().unwrap_or_default()) {
            Ok(())
        } else {
            tracing::error!(
                "Unauthorized audience domain: {}",
                url.host_str().unwrap_or_default()
            );
            Err(ApiError::BadRequest)
        }
    }
}

impl NewToken {
    pub fn new(user: &User, token_type: TokenType, app_state: &AppState) -> Result<Self, ApiError> {
        let (aud, azp, duration) = match token_type {
            TokenType::Access => (
                "access".to_string(),
                None,
                Duration::minutes(app_state.config.access_token_maxage),
            ),
            TokenType::Refresh => (
                "refresh".to_string(),
                None,
                Duration::days(app_state.config.refresh_token_maxage),
            ),
            TokenType::ThirdParty { aud, azp } => {
                // Validate the audience URL against allowed domains
                TokenType::validate_third_party_audience(&aud, &app_state.app_mode)?;

                // For now, enforce that azp must be "maple"
                if azp != "maple" {
                    return Err(ApiError::BadRequest);
                }
                (aud, Some(azp), Duration::hours(1))
            }
        };

        let custom_claims = CustomClaims {
            sub: user.get_id().to_string(),
            aud,
            azp,
        };

        tracing::debug!("Creating new token with claims: {:?}", custom_claims);

        let time_options = TimeOptions::default();
        let claims = Claims::new(custom_claims).set_duration_and_issuance(&time_options, duration);

        // Create header with typ field
        let header = Header::empty().with_token_type("JWT");

        let es256k = Es256k::<Sha256>::new(app_state.config.jwt_keys.secp.clone());

        let token_string = es256k
            .token(&header, &claims, &app_state.config.jwt_keys.signing_key)
            .map_err(|e| {
                tracing::error!("Error creating token: {:?}", e);
                ApiError::InternalServerError
            })?;

        tracing::debug!("Successfully created token");

        Ok(Self {
            token: token_string,
        })
    }
}

pub async fn generate_jwt_secret(
    aws_credential_manager: Arc<tokio::sync::RwLock<Option<AwsCredentialManager>>>,
) -> Result<Vec<u8>, Error> {
    tracing::info!("Generating new JWT secret");
    if let Some(cred_manager) = aws_credential_manager.read().await.as_ref().cloned() {
        let aws_creds = cred_manager
            .get_credentials()
            .await
            .expect("should have creds");

        generate_random_bytes_from_enclave(
            &aws_creds.region,
            &aws_creds.access_key_id,
            &aws_creds.secret_access_key,
            &aws_creds.token,
            32,
        )
        .await
        .map_err(|e| Error::EncryptionError(e.to_string()))
    } else {
        Ok(crate::encrypt::generate_random::<32>().to_vec())
    }
}

pub async fn validate_jwt(
    State(data): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    tracing::debug!("Entering validate_jwt");
    let token = match req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|auth_header| auth_header.to_str().ok())
        .and_then(|auth_value| auth_value.strip_prefix("Bearer ").map(ToString::to_string))
    {
        Some(token) => token,
        None => return ApiError::InvalidJwt.into_response(),
    };

    tracing::trace!("Validating JWT");

    let claims = match validate_token(&token, &data, "access") {
        Ok(claims) => claims,
        Err(_) => return ApiError::InvalidJwt.into_response(),
    };

    let user_uuid: Uuid = match Uuid::parse_str(&claims.sub) {
        Ok(uuid) => uuid,
        Err(e) => {
            tracing::error!("Error parsing user uuid: {:?}", e);
            return ApiError::InvalidJwt.into_response();
        }
    };

    let user = match data.get_user(user_uuid).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Error getting user: {:?}", e);
            return ApiError::InternalServerError.into_response();
        }
    };

    req.extensions_mut().insert(user);
    tracing::debug!("Exiting validate_jwt");
    next.run(req).await
}

pub(crate) fn validate_token(
    original_token: &str,
    data: &AppState,
    expected_audience: &str,
) -> Result<CustomClaims, ApiError> {
    // Try ES256K first
    let es256k = Es256k::<Sha256>::new(data.config.jwt_keys.secp.clone());
    let public_key = data.config.jwt_keys.public_key();

    tracing::trace!("Attempting to validate ES256K token");

    // First parse the token with the correct type
    let parsed_token = match UntrustedToken::new(original_token) {
        Ok(token) => token,
        Err(e) => {
            tracing::error!("Failed to parse token: {:?}", e);
            return Err(ApiError::InvalidJwt);
        }
    };

    // Deserialize claims first
    let token: Token<CustomClaims> = match es256k.validator(&public_key).validate(&parsed_token) {
        Ok(token) => {
            tracing::trace!("ES256K signature validation successful");

            // Only validate expiration, not maturity
            let time_options = TimeOptions::default();
            if let Err(e) = token.claims().validate_expiration(&time_options) {
                tracing::error!("Token expired: {:?}", e);
                return Err(ApiError::InvalidJwt);
            }

            // Validate audience with proper type annotation
            let claims: &Claims<CustomClaims> = token.claims();
            if claims.custom.aud != expected_audience {
                tracing::error!(
                    "Invalid audience: got {}, expected {}",
                    claims.custom.aud,
                    expected_audience
                );
                return Err(ApiError::InvalidJwt);
            }

            token
        }
        Err(e) => {
            tracing::debug!("ES256K validation failed: {:?}, trying legacy HMAC", e);

            // Try legacy HMAC validation
            use jsonwebtoken::{decode, DecodingKey, Validation};
            let mut hmac_validation = Validation::default();
            hmac_validation.validate_exp = true;
            hmac_validation.set_audience(&[expected_audience]); // Only accept expected audience

            match decode::<CustomClaims>(
                original_token,
                &DecodingKey::from_secret(&data.config.jwt_keys.legacy_secret),
                &hmac_validation,
            ) {
                Ok(token_data) => {
                    tracing::debug!("Legacy HMAC validation successful");
                    return Ok(token_data.claims);
                }
                Err(e) => {
                    tracing::error!("Legacy HMAC validation failed: {:?}", e);
                    return Err(ApiError::InvalidJwt);
                }
            }
        }
    };

    // Return the claims
    Ok(token.claims().custom.clone())
}
