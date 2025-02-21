use crate::{
    email::send_platform_verification_email,
    jwt::{NewToken, TokenType},
    models::{email_verification::NewEmailVerification, platform_users::NewPlatformUser},
    web::encryption_middleware::{decrypt_request, encrypt_response, EncryptedResponse},
    ApiError, AppState,
};
use axum::{
    extract::State, middleware::from_fn_with_state, routing::post, Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::spawn;
use tracing::{debug, error};
use uuid::Uuid;
use validator::Validate;

#[derive(Deserialize, Clone, Validate)]
pub struct PlatformLoginRequest {
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(max = 255, message = "Email must not exceed 255 characters"))]
    pub email: String,

    #[validate(length(
        min = 8,
        max = 64,
        message = "Password must be between 8 and 64 characters"
    ))]
    pub password: String,
}

#[derive(Deserialize, Clone, Validate)]
pub struct PlatformRegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(max = 255, message = "Email must not exceed 255 characters"))]
    pub email: String,

    #[validate(length(
        min = 8,
        max = 64,
        message = "Password must be between 8 and 64 characters"
    ))]
    pub password: String,

    #[validate(length(max = 50, message = "Name must not exceed 50 characters"))]
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct PlatformAuthResponse {
    pub id: Uuid,
    pub email: String,
    pub name: Option<String>,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize, Clone, Validate)]
pub struct PlatformRefreshRequest {
    #[validate(length(min = 1, message = "Refresh token cannot be empty"))]
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct PlatformRefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub fn router(app_state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route(
            "/platform/login",
            post(login_platform_user).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<PlatformLoginRequest>,
            )),
        )
        .route(
            "/platform/register",
            post(register_platform_user).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<PlatformRegisterRequest>,
            )),
        )
        .route(
            "/platform/refresh",
            post(refresh_platform_token).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<PlatformRefreshRequest>,
            )),
        )
        .with_state(app_state)
}

pub async fn login_platform_user(
    State(data): State<Arc<AppState>>,
    Extension(login_request): Extension<PlatformLoginRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<PlatformAuthResponse>>, ApiError> {
    debug!("Entering login_platform_user function");

    // Validate request
    if let Err(errors) = login_request.validate() {
        error!("Validation error: {:?}", errors);
        return Err(ApiError::BadRequest);
    }

    let auth_response = login_internal_platform(data.clone(), login_request).await?;
    let result = encrypt_response(&data, &session_id, &auth_response).await;
    debug!("Exiting login_platform_user function");
    result
}

async fn login_internal_platform(
    data: Arc<AppState>,
    login_request: PlatformLoginRequest,
) -> Result<PlatformAuthResponse, ApiError> {
    // Authenticate the platform user
    match data
        .authenticate_platform_user(&login_request.email, login_request.password)
        .await
    {
        Ok(Some(platform_user)) => {
            // Generate tokens
            let access_token =
                NewToken::new_for_platform_user(&platform_user, TokenType::Access, &data)?;
            let refresh_token =
                NewToken::new_for_platform_user(&platform_user, TokenType::Refresh, &data)?;

            let auth_response = PlatformAuthResponse {
                id: platform_user.uuid,
                email: platform_user.email,
                name: platform_user.name,
                access_token: access_token.token,
                refresh_token: refresh_token.token,
            };
            Ok(auth_response)
        }
        Ok(None) => {
            error!("Invalid login attempt for platform user");
            Err(ApiError::InvalidUsernameOrPassword)
        }
        Err(e) => {
            error!("Error authenticating platform user: {:?}", e);
            Err(ApiError::InternalServerError)
        }
    }
}

pub async fn register_platform_user(
    State(data): State<Arc<AppState>>,
    Extension(register_request): Extension<PlatformRegisterRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<PlatformAuthResponse>>, ApiError> {
    debug!("Entering register_platform_user function");

    // Validate request
    if let Err(errors) = register_request.validate() {
        error!("Validation error: {:?}", errors);
        return Err(ApiError::BadRequest);
    }

    // Check if user already exists
    if data
        .db
        .get_platform_user_by_email(&register_request.email)?
        .is_some()
    {
        return Err(ApiError::EmailAlreadyExists);
    }

    // Hash and encrypt the password
    let password_hash = password_auth::generate_hash(register_request.password);
    let secret_key = secp256k1::SecretKey::from_slice(&data.enclave_key)
        .map_err(|_| ApiError::InternalServerError)?;
    let encrypted_password =
        crate::encrypt::encrypt_with_key(&secret_key, password_hash.as_bytes()).await;

    // Create the platform user
    let new_platform_user =
        NewPlatformUser::new(register_request.email.clone(), Some(encrypted_password))
            .with_name(register_request.name.unwrap_or_default());

    let platform_user = data
        .db
        .create_platform_user(new_platform_user)
        .map_err(|e| {
            error!("Failed to create platform user: {:?}", e);
            ApiError::InternalServerError
        })?;

    // Create email verification
    let new_verification = NewEmailVerification::new(platform_user.uuid, 24, false);
    let verification = match data.db.create_email_verification(new_verification) {
        Ok(v) => v,
        Err(e) => {
            error!("Error creating email verification: {:?}", e);
            return Err(ApiError::InternalServerError);
        }
    };

    // Send verification email in background
    let email = register_request.email.clone();
    let verification_code = verification.verification_code;
    let app_state = data.clone();

    spawn(async move {
        if let Err(e) = send_platform_verification_email(
            &app_state,
            app_state.resend_api_key.clone(),
            email,
            verification_code,
        )
        .await
        {
            error!("Could not send verification email: {}", e);
        }
    });

    // Generate tokens
    let access_token = NewToken::new_for_platform_user(&platform_user, TokenType::Access, &data)?;
    let refresh_token = NewToken::new_for_platform_user(&platform_user, TokenType::Refresh, &data)?;

    let response = PlatformAuthResponse {
        id: platform_user.uuid,
        email: platform_user.email,
        name: platform_user.name,
        access_token: access_token.token,
        refresh_token: refresh_token.token,
    };

    let result = encrypt_response(&data, &session_id, &response).await;
    debug!("Exiting register_platform_user function");
    result
}

pub async fn refresh_platform_token(
    State(data): State<Arc<AppState>>,
    Extension(refresh_request): Extension<PlatformRefreshRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<PlatformRefreshResponse>>, ApiError> {
    debug!("Entering refresh_platform_token function");

    // Validate request
    if let Err(errors) = refresh_request.validate() {
        error!("Validation error: {:?}", errors);
        return Err(ApiError::BadRequest);
    }

    let claims = crate::jwt::validate_token(&refresh_request.refresh_token, &data, "refresh")?;
    let platform_user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiError::InvalidJwt)?;

    // Verify platform user still exists
    let platform_user = data.db.get_platform_user_by_uuid(platform_user_id)?;

    // Generate new tokens
    let new_access_token =
        NewToken::new_for_platform_user(&platform_user, TokenType::Access, &data)?;
    let new_refresh_token =
        NewToken::new_for_platform_user(&platform_user, TokenType::Refresh, &data)?;

    let response = PlatformRefreshResponse {
        access_token: new_access_token.token,
        refresh_token: new_refresh_token.token,
    };

    let result = encrypt_response(&data, &session_id, &response).await;
    debug!("Exiting refresh_platform_token function");
    result
}
