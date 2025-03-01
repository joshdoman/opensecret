use crate::decrypt_with_key;
use crate::models::email_verification::NewEmailVerification;
use crate::models::oauth::NewUserOAuthConnection;
use crate::oauth::OAuthState;
use crate::web::encryption_middleware::{decrypt_request, encrypt_response, EncryptedResponse};
use crate::web::login_routes::handle_new_user_registration;
use crate::web::platform::PROJECT_GITHUB_OAUTH_SECRET;
use crate::web::platform::PROJECT_GOOGLE_OAUTH_SECRET;
use crate::GithubProvider;
use crate::GoogleProvider;
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
use base64::Engine as _;
use oauth2::TokenResponse;
use oauth2::{basic::BasicClient, AuthorizationCode};
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
pub struct OAuthOAuthCallbackResponse {
    auth_url: String,
    state: String,
}

#[derive(Deserialize, Clone)]
pub struct OAuthAuthRequest {
    pub client_id: Uuid,
}

#[derive(Deserialize, Clone)]
pub struct OAuthCallbackRequest {
    pub code: String,
    pub state: String,
}

#[derive(Serialize)]
pub struct OAuthCallbackResponse {
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

async fn get_project_oauth_client(
    app_state: &AppState,
    project_id: i32,
    provider_name: &str,
) -> Result<BasicClient, ApiError> {
    // Get project OAuth settings
    let oauth_settings = app_state
        .db
        .get_project_oauth_settings(project_id)?
        .ok_or_else(|| {
            error!("OAuth settings not found for project");
            ApiError::BadRequest
        })?;

    // Get provider settings based on provider name
    let (enabled, provider_settings, secret_key) = match provider_name {
        "github" => {
            let enabled = oauth_settings.github_oauth_enabled;
            let settings = oauth_settings.github_oauth_settings;
            let secret = app_state
                .db
                .get_org_project_secret_by_key_name_and_project(
                    PROJECT_GITHUB_OAUTH_SECRET,
                    project_id,
                )?;
            (enabled, settings, secret)
        }
        "google" => {
            let enabled = oauth_settings.google_oauth_enabled;
            let settings = oauth_settings.google_oauth_settings;
            let secret = app_state
                .db
                .get_org_project_secret_by_key_name_and_project(
                    PROJECT_GOOGLE_OAUTH_SECRET,
                    project_id,
                )?;
            (enabled, settings, secret)
        }
        _ => {
            error!("Unsupported OAuth provider: {}", provider_name);
            return Err(ApiError::BadRequest);
        }
    };

    // Verify OAuth is enabled for this provider
    if !enabled {
        error!("{} OAuth is not enabled for this project", provider_name);
        return Err(ApiError::BadRequest);
    }

    // Get provider settings
    let provider_settings = provider_settings.ok_or_else(|| {
        error!("{} OAuth settings not configured", provider_name);
        ApiError::BadRequest
    })?;

    // Get and decrypt client secret
    let secret = secret_key.ok_or_else(|| {
        error!("{} OAuth secret not found", provider_name);
        ApiError::BadRequest
    })?;

    let secret_key = SecretKey::from_slice(&app_state.enclave_key).map_err(|_| {
        error!("Failed to create secret key from enclave key");
        ApiError::InternalServerError
    })?;

    let client_secret = String::from_utf8(
        decrypt_with_key(&secret_key, &secret.secret_enc).map_err(|_| {
            error!("Failed to decrypt OAuth client secret");
            ApiError::InternalServerError
        })?,
    )
    .map_err(|_| {
        error!("Failed to parse decrypted OAuth client secret as UTF-8");
        ApiError::InternalServerError
    })?;

    // Get the OAuth provider
    let oauth_provider = app_state
        .oauth_manager
        .get_provider(provider_name)
        .ok_or_else(|| {
            error!("{} provider not initialized", provider_name);
            ApiError::InternalServerError
        })?;

    // Build and return the client using the trait method
    oauth_provider
        .build_client(
            provider_settings.client_id,
            client_secret,
            provider_settings.redirect_url,
        )
        .await
        .map_err(|_| ApiError::InternalServerError)
}

pub async fn initiate_oauth(
    State(app_state): State<Arc<AppState>>,
    Extension(auth_request): Extension<OAuthAuthRequest>,
    Extension(session_id): Extension<Uuid>,
    provider_name: &str,
) -> Result<Json<EncryptedResponse<OAuthOAuthCallbackResponse>>, ApiError> {
    debug!("Entering init {} auth function", provider_name);

    // Get project
    let project = app_state
        .db
        .get_org_project_by_client_id(auth_request.client_id)
        .map_err(|_| ApiError::BadRequest)?;

    // Get OAuth client for this project
    let oauth_client = get_project_oauth_client(&app_state, project.id, provider_name).await?;

    // Get the OAuth provider
    let oauth_provider = app_state
        .oauth_manager
        .get_provider(provider_name)
        .ok_or_else(|| {
            error!("{} provider not initialized", provider_name);
            ApiError::InternalServerError
        })?;

    // Generate initial authorization URL to get the CSRF token
    let (initial_url, csrf_token) = oauth_provider.generate_authorize_url(&oauth_client).await;

    // Create our state that includes both CSRF token and client_id
    let state = OAuthState {
        csrf_token: csrf_token.secret().clone(),
        client_id: project.client_id,
    };

    // Store the complete state in the provider
    oauth_provider
        .store_state(csrf_token.secret(), state.clone())
        .await;

    let state_json = serde_json::to_string(&state).map_err(|_| ApiError::InternalServerError)?;
    let state_base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(state_json);

    // Replace the CSRF token in the URL with our encoded state
    let auth_url = initial_url.replace(csrf_token.secret(), &state_base64);

    let response = OAuthOAuthCallbackResponse {
        auth_url,
        state: state_base64,
    };

    debug!("Exiting init {} auth function", provider_name);
    encrypt_response(&app_state, &session_id, &response).await
}

pub async fn oauth_callback(
    State(app_state): State<Arc<AppState>>,
    Extension(callback_request): Extension<OAuthCallbackRequest>,
    Extension(session_id): Extension<Uuid>,
    provider_name: &str,
) -> Result<Json<EncryptedResponse<OAuthCallbackResponse>>, ApiError> {
    debug!("Entering {} callback function", provider_name);
    debug!("Received code: {}", callback_request.code);
    debug!("Received state: {}", callback_request.state);

    // Decode and parse the state
    let state_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&callback_request.state)
        .map_err(|e| {
            error!("Could not parse state: {:?}", e);
            ApiError::BadRequest
        })?;
    debug!("Parsed state from request");
    let state: OAuthState = serde_json::from_slice(&state_json).map_err(|e| {
        error!("Could not parse OAuthState: {:?}", e);
        ApiError::BadRequest
    })?;
    debug!("Converted state to OAuthState");

    // Get the OAuth provider
    let oauth_provider = app_state
        .oauth_manager
        .get_provider(provider_name)
        .ok_or_else(|| {
            error!("{} provider not initialized", provider_name);
            ApiError::InternalServerError
        })?;

    // Validate the complete state (both CSRF token and client_id)
    let is_valid = oauth_provider.validate_state(&state).await;

    if !is_valid {
        error!("Invalid state in {} callback", provider_name);
        return Err(ApiError::BadRequest);
    }

    // Get project (we can trust the client_id now since we validated it against our stored state)
    debug!("Getting project from client_id: {:?}", state.client_id);
    let project = app_state
        .db
        .get_org_project_by_client_id(state.client_id)
        .map_err(|e| {
            error!(
                "Could not get project by client {:?} id: {:?}",
                state.client_id, e
            );
            ApiError::BadRequest
        })?;

    // Get OAuth client for this project
    let oauth_client = get_project_oauth_client(&app_state, project.id, provider_name).await?;

    // Exchange the code for an access token
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(callback_request.code.clone()))
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| {
            error!("Failed to exchange code for access token: {:?}", e);
            ApiError::InternalServerError
        })?;

    let access_token = token.access_token().secret().to_string();

    // Fetch user information and find or create the user
    let user = match provider_name {
        "github" => {
            debug!("Access token obtained, fetching GitHub user");
            // Get GitHub provider for GitHub-specific operations
            let github_provider = oauth_provider.as_github().ok_or_else(|| {
                error!("Failed to get GithubProvider");
                ApiError::InternalServerError
            })?;
            let github_user = match fetch_github_user(&access_token, github_provider).await {
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
                access_token,
                github_user.name.clone().or(Some(github_user.login.clone())),
                project.id,
            )
            .await?
        }
        "google" => {
            debug!("Access token obtained, fetching Google user");
            // Get Google provider for Google-specific operations
            let google_provider = oauth_provider.as_google().ok_or_else(|| {
                error!("Failed to get GoogleProvider");
                ApiError::InternalServerError
            })?;
            let google_user = match fetch_google_user(&access_token, google_provider).await {
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
                access_token,
                google_user.name.clone(),
                project.id,
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
        email: user
            .get_email()
            .expect("OAuth user must have email")
            .to_string(),
        access_token: access_token.token,
        refresh_token: refresh_token.token,
    };

    debug!("Exiting {} callback function", provider_name);
    encrypt_response(&app_state, &session_id, &auth_response).await
}

async fn fetch_github_user(
    access_token: &str,
    github_provider: &GithubProvider,
) -> Result<GithubUser, ApiError> {
    let client = reqwest::Client::new();
    let user_url = &github_provider.user_info_url;

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

async fn fetch_google_user(
    access_token: &str,
    google_provider: &GoogleProvider,
) -> Result<GoogleUser, ApiError> {
    let client = reqwest::Client::new();
    let user_url = &google_provider.user_info_url;

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
    user_name: Option<String>,
    project_id: i32,
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
    match app_state.db.get_user_by_email(email.clone(), project_id) {
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
            // Create new user
            let new_user = NewUser::new(Some(email.clone()), None, project_id)
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
