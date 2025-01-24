use crate::models::email_verification::NewEmailVerification;
use crate::models::oauth::NewUserOAuthConnection;
use crate::web::encryption_middleware::{decrypt_request, encrypt_response, EncryptedResponse};
use crate::web::login_routes::{handle_new_user_registration, VALID_INVITE_CODES};
use crate::AppMode;
use crate::{encrypt, DBError};
use crate::{
    jwt::{NewToken, TokenType},
    models::users::{NewUser, User},
    ApiError, AppState,
};
use axum::{
    extract::{Extension, State},
    routing::post,
    Json, Router,
};
use reqwest::header::AUTHORIZATION;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, trace};
use uuid::Uuid;

pub fn router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/auth/github",
            post(|state, ext1, ext2| initiate_oauth(state, ext1, ext2, "github")).layer(
                axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    decrypt_request::<OAuthAuthRequest>,
                ),
            ),
        )
        .route(
            "/auth/github/callback",
            post(|state, ext1, ext2| oauth_callback(state, ext1, ext2, "github")).layer(
                axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    decrypt_request::<OAuthCallbackRequest>,
                ),
            ),
        )
        .route(
            "/auth/google",
            post(|state, ext1, ext2| initiate_oauth(state, ext1, ext2, "google")).layer(
                axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    decrypt_request::<OAuthAuthRequest>,
                ),
            ),
        )
        .route(
            "/auth/google/callback",
            post(|state, ext1, ext2| oauth_callback(state, ext1, ext2, "google")).layer(
                axum::middleware::from_fn_with_state(
                    app_state.clone(),
                    decrypt_request::<OAuthCallbackRequest>,
                ),
            ),
        )
        .with_state(app_state)
}

#[derive(Serialize)]
struct OAuthOAuthCallbackResponse {
    auth_url: String,
    csrf_token: String,
}

#[derive(Deserialize, Clone)]
struct OAuthAuthRequest {
    invite_code: Option<String>,
}

#[derive(Deserialize, Clone)]
struct OAuthCallbackRequest {
    code: String,
    state: String,
    invite_code: String,
}

#[derive(Serialize)]
struct OAuthCallbackResponse {
    id: Uuid,
    email: String,
    access_token: String,
    refresh_token: String,
}

#[derive(Deserialize, Clone, Debug)]
struct GithubUser {
    id: i64,
    login: String,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[derive(Deserialize, Clone, Debug)]
struct GoogleUser {
    sub: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
}

async fn initiate_oauth(
    State(app_state): State<Arc<AppState>>,
    Extension(auth_request): Extension<OAuthAuthRequest>,
    Extension(session_id): Extension<Uuid>,
    provider_name: &str,
) -> Result<Json<EncryptedResponse<OAuthOAuthCallbackResponse>>, ApiError> {
    debug!("Entering init {} auth function", provider_name);

    // Check the invite code if it's provided (for sign-ups)
    if let Some(invite_code) = &auth_request.invite_code {
        let lowercase_invite_code = invite_code.to_lowercase();
        if !VALID_INVITE_CODES.contains(&lowercase_invite_code.as_str()) {
            error!("Invalid invite code: {}", lowercase_invite_code);
            return Err(ApiError::InvalidInviteCode);
        }
    }

    let oauth_client = app_state
        .oauth_manager
        .get_provider(provider_name)
        .ok_or(ApiError::InternalServerError)?;

    let (auth_url, csrf_token) = oauth_client.generate_authorize_url().await;

    let response = OAuthOAuthCallbackResponse {
        auth_url,
        csrf_token: csrf_token.secret().clone(),
    };

    debug!("Exiting init {} auth function", provider_name);
    encrypt_response(&app_state, &session_id, &response).await
}

async fn oauth_callback(
    State(app_state): State<Arc<AppState>>,
    Extension(callback_request): Extension<OAuthCallbackRequest>,
    Extension(session_id): Extension<Uuid>,
    provider_name: &str,
) -> Result<Json<EncryptedResponse<OAuthCallbackResponse>>, ApiError> {
    debug!("Entering {} callback function", provider_name);
    trace!("Received code: {}", callback_request.code);
    trace!("Received state: {}", callback_request.state);
    trace!("Received invite code: {}", callback_request.invite_code);

    let oauth_client = app_state
        .oauth_manager
        .get_provider(provider_name)
        .ok_or_else(|| {
            error!("{} client not initialized", provider_name);
            ApiError::InternalServerError
        })?;

    // Validate the state
    if !oauth_client.validate_state(&callback_request.state).await {
        error!("Invalid state in {} callback", provider_name);
        return Err(ApiError::BadRequest);
    }

    // Exchange the code for an access token
    let token = match oauth_client
        .exchange_code(callback_request.code.clone())
        .await
    {
        Ok(token) => {
            debug!("Successfully exchanged code for token");
            token
        }
        Err(e) => {
            error!("Failed to exchange code for access token: {:?}", e);
            return Err(ApiError::InternalServerError);
        }
    };

    // Fetch user information and find or create the user
    let user = match provider_name {
        "github" => {
            debug!("Access token obtained, fetching GitHub user");
            let github_user = match fetch_github_user(token.secret()).await {
                Ok(user) => {
                    debug!("Successfully fetched GitHub user");
                    user
                }
                Err(e) => {
                    error!("Failed to fetch GitHub user: {:?}", e);
                    return Err(e);
                }
            };

            find_or_create_user_from_oauth(
                &app_state,
                github_user.email.clone().unwrap_or_default(),
                github_user.id.to_string(),
                "github",
                token.secret().to_string(),
                &callback_request.invite_code,
                github_user.name.clone().or(Some(github_user.login.clone())),
            )
            .await?
        }
        "google" => {
            debug!("Access token obtained, fetching Google user");
            let google_user = match fetch_google_user(token.secret()).await {
                Ok(user) => {
                    debug!("Successfully fetched Google user");
                    user
                }
                Err(e) => {
                    error!("Failed to fetch Google user: {:?}", e);
                    return Err(e);
                }
            };

            find_or_create_user_from_oauth(
                &app_state,
                google_user.email.clone(),
                google_user.sub.clone(),
                "google",
                token.secret().to_string(),
                &callback_request.invite_code,
                google_user.name.clone(),
            )
            .await?
        }
        _ => {
            error!("Unsupported provider: {}", provider_name);
            return Err(ApiError::InternalServerError);
        }
    };

    // Generate JWT tokens
    let access_token = NewToken::new(&user, TokenType::Access, &app_state).map_err(|e| {
        error!("Failed to generate access token: {:?}", e);
        ApiError::InternalServerError
    })?;
    let refresh_token = NewToken::new(&user, TokenType::Refresh, &app_state).map_err(|e| {
        error!("Failed to generate refresh token: {:?}", e);
        ApiError::InternalServerError
    })?;

    let auth_response = OAuthCallbackResponse {
        id: user.get_id(),
        email: user.get_email()
            .expect("OAuth user must have email")
            .to_string(),
        access_token: access_token.token,
        refresh_token: refresh_token.token,
    };

    debug!("Exiting {} callback function", provider_name);
    encrypt_response(&app_state, &session_id, &auth_response).await
}

async fn fetch_github_user(access_token: &str) -> Result<GithubUser, ApiError> {
    let client = reqwest::Client::new();
    let user_url = "https://api.github.com/user";

    debug!("Sending request to GitHub API: {}", user_url);
    let response = client
        .get(user_url)
        .header("Authorization", format!("token {}", access_token))
        .header("User-Agent", "OpenSecret")
        .send()
        .await
        .map_err(|e| {
            error!("Failed to send request to GitHub API: {:?}", e);
            ApiError::InternalServerError
        })?;

    // Get status and headers before consuming the response
    let status = response.status();
    let headers = response.headers().clone();
    debug!("GitHub API response status: {}", status);
    trace!("GitHub API response headers: {:?}", headers);

    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read error body".to_string());
        error!(
            "GitHub API returned non-success status: {} {}",
            status,
            status.canonical_reason().unwrap_or("")
        );
        error!("Error response body: {}", error_body);
        return Err(ApiError::InternalServerError);
    }

    let user_body = response.text().await.map_err(|e| {
        error!("Failed to read GitHub user response body: {:?}", e);
        ApiError::InternalServerError
    })?;

    trace!("GitHub user response body: {}", user_body);

    let mut github_user: GithubUser = serde_json::from_str(&user_body).map_err(|e| {
        error!("Failed to parse GitHub user JSON: {:?}", e);
        error!("GitHub user response body: {}", user_body);
        ApiError::InternalServerError
    })?;

    // If the email is not public, fetch the email separately
    if github_user.email.is_none() {
        let emails_url = "https://api.github.com/user/emails";
        debug!("Fetching GitHub user emails: {}", emails_url);
        let emails_response = client
            .get(emails_url)
            .header("Authorization", format!("token {}", access_token))
            .header("User-Agent", "OpenSecret")
            .send()
            .await
            .map_err(|e| {
                error!("Failed to send request for GitHub user emails: {:?}", e);
                ApiError::InternalServerError
            })?;

        let emails_status = emails_response.status();
        let emails_headers = emails_response.headers().clone();
        trace!("GitHub emails API response status: {}", emails_status);
        trace!("GitHub emails API response headers: {:?}", emails_headers);

        if !emails_status.is_success() {
            let error_body = emails_response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read error body".to_string());
            error!(
                "GitHub API returned non-success status for emails: {} {}",
                emails_status,
                emails_status.canonical_reason().unwrap_or("")
            );
            error!("Error response body for emails: {}", error_body);
            return Err(ApiError::InternalServerError);
        }

        let emails_body = emails_response.text().await.map_err(|e| {
            error!("Failed to read GitHub emails response body: {:?}", e);
            ApiError::InternalServerError
        })?;

        trace!("GitHub emails response body: {}", emails_body);

        let emails: Vec<GithubEmail> = serde_json::from_str(&emails_body).map_err(|e| {
            error!("Failed to parse GitHub emails JSON: {:?}", e);
            error!("GitHub emails response body: {}", emails_body);
            ApiError::InternalServerError
        })?;

        github_user.email = emails
            .into_iter()
            .find(|e| e.primary && e.verified)
            .map(|e| e.email);
    }

    // If we still don't have an email, return an error
    if github_user.email.is_none() {
        error!("No valid email found for GitHub user");
        return Err(ApiError::NoEmailFound);
    }

    Ok(github_user)
}

async fn fetch_google_user(access_token: &str) -> Result<GoogleUser, ApiError> {
    let client = reqwest::Client::new();
    let user_url = "https://www.googleapis.com/oauth2/v3/userinfo";

    debug!("Sending request to Google API: {}", user_url);
    let response = client
        .get(user_url)
        .header(AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await
        .map_err(|e| {
            error!("Failed to send request to Google API: {:?}", e);
            ApiError::InternalServerError
        })?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read error body".to_string());
        error!(
            "Google API returned non-success status: {} {}",
            status, error_body
        );
        return Err(ApiError::InternalServerError);
    }

    let google_user: GoogleUser = response.json().await.map_err(|e| {
        error!("Failed to parse Google user JSON: {:?}", e);
        ApiError::InternalServerError
    })?;

    // Ensure email is present and verified
    if google_user.email.is_empty() || !google_user.email_verified {
        error!("Google user email is not present or not verified");
        return Err(ApiError::BadRequest);
    }

    Ok(google_user)
}

async fn find_or_create_user_from_oauth(
    app_state: &AppState,
    email: String,
    provider_user_id: String,
    provider_name: &str,
    access_token: String,
    invite_code: &str,
    user_name: Option<String>,
) -> Result<User, ApiError> {
    let provider = app_state
        .db
        .get_oauth_provider_by_name(provider_name)
        .map_err(|e| {
            error!("Failed to get {} OAuth provider: {:?}", provider_name, e);
            ApiError::InternalServerError
        })?
        .ok_or_else(|| {
            error!("{} OAuth provider not found", provider_name);
            ApiError::InternalServerError
        })?;

    // Try to find the user by email
    match app_state.db.get_user_by_email(email.clone()) {
        Ok(existing_user) => {
            // User exists, check if they have a connection with the provider
            let existing_connection = app_state
                .db
                .get_user_oauth_connection_by_user_and_provider(existing_user.uuid, provider.id)
                .map_err(|e| {
                    error!("Failed to get existing OAuth connection: {:?}", e);
                    ApiError::InternalServerError
                })?;

            if existing_connection.is_some() {
                // User has already linked their account, update the token
                update_provider_connection(app_state, &existing_user, provider.id, &access_token)
                    .await?;
                Ok(existing_user)
            } else {
                // User exists but hasn't linked the provider before
                error!("User exists but hasn't linked {} before", provider_name);
                Err(ApiError::UserExistsNotLinked)
            }
        }
        Err(DBError::UserNotFound) => {
            // If invite code is empty and not in preview mode, return UserNotFound error
            if invite_code.is_empty() && app_state.app_mode != AppMode::Preview {
                return Err(ApiError::UserNotFound);
            }

            // Check the invite code for new sign-ups, but skip for preview mode
            if app_state.app_mode != AppMode::Preview {
                let lowercase_invite_code = invite_code.to_lowercase();
                if !VALID_INVITE_CODES.contains(&lowercase_invite_code.as_str()) {
                    error!(
                        "Invalid invite code for new user: {}",
                        lowercase_invite_code
                    );
                    return Err(ApiError::InvalidInviteCode);
                }
            }

            // Create new user
            let new_user = NewUser::new(Some(email.clone()), None)
                .with_name(user_name.unwrap_or_default());

            let user = app_state.db.create_user(new_user).map_err(|e| {
                error!("Failed to create new user: {:?}", e);
                ApiError::InternalServerError
            })?;

            // Create connection for the new user
            create_provider_connection(
                app_state,
                &user,
                provider.id,
                provider_user_id,
                &access_token,
            )
            .await?;

            // Create email verification entry as already verified
            let new_verification = NewEmailVerification::new(user.uuid, 24, true);
            app_state
                .db
                .create_email_verification(new_verification)
                .map_err(|e| {
                    error!("Error creating email verification: {:?}", e);
                    ApiError::InternalServerError
                })?;

            // Handle new user registration
            handle_new_user_registration(app_state, &user, false).await?;

            Ok(user)
        }
        Err(e) => {
            error!("Database error when fetching user: {:?}", e);
            Err(ApiError::InternalServerError)
        }
    }
}

async fn update_provider_connection(
    app_state: &AppState,
    user: &User,
    provider_id: i32,
    access_token: &str,
) -> Result<(), ApiError> {
    let encrypted_access_token = encrypt_access_token(app_state, access_token).await?;

    let mut connection = app_state
        .db
        .get_user_oauth_connection_by_user_and_provider(user.uuid, provider_id)
        .map_err(|e| {
            error!("Failed to get existing OAuth connection: {:?}", e);
            ApiError::InternalServerError
        })?
        .expect("Connection should exist");

    connection.access_token_enc = encrypted_access_token;
    app_state
        .db
        .update_user_oauth_connection(&connection)
        .map_err(|e| {
            error!("Failed to update OAuth connection: {:?}", e);
            ApiError::InternalServerError
        })?;

    Ok(())
}

async fn create_provider_connection(
    app_state: &AppState,
    user: &User,
    provider_id: i32,
    provider_user_id: String,
    access_token: &str,
) -> Result<(), ApiError> {
    let encrypted_access_token = encrypt_access_token(app_state, access_token).await?;

    let new_connection = NewUserOAuthConnection {
        user_id: user.uuid,
        provider_id,
        provider_user_id,
        access_token_enc: encrypted_access_token,
        refresh_token_enc: None, // Assuming no refresh tokens for both providers
        expires_at: None,        // Assuming tokens don't expire unless revoked
    };

    app_state
        .db
        .create_user_oauth_connection(new_connection)
        .map_err(|e| {
            error!("Failed to create new OAuth connection: {:?}", e);
            ApiError::InternalServerError
        })?;

    Ok(())
}

async fn encrypt_access_token(
    app_state: &AppState,
    access_token: &str,
) -> Result<Vec<u8>, ApiError> {
    let secret_key = SecretKey::from_slice(&app_state.enclave_key).map_err(|e| {
        error!("Failed to create SecretKey from enclave key: {:?}", e);
        ApiError::InternalServerError
    })?;
    Ok(encrypt::encrypt_with_key(&secret_key, access_token.as_bytes()).await)
}
