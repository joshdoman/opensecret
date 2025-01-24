use crate::db::DBConnection;
use crate::models::oauth::NewOAuthProvider;
use crate::Error;
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct GithubProvider {
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub client: BasicClient,
    pub state_store: Arc<RwLock<HashMap<String, CsrfToken>>>,
}

impl GithubProvider {
    pub async fn new(
        db: Arc<dyn DBConnection + Send + Sync>,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> Result<Self, Error> {
        let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
            .map_err(|e| Error::OAuthError(format!("Invalid auth URL: {}", e)))?;
        let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
            .map_err(|e| Error::OAuthError(format!("Invalid token URL: {}", e)))?;

        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            auth_url.clone(),
            Some(token_url.clone()),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url)
                .map_err(|e| Error::OAuthError(format!("Invalid redirect URL: {}", e)))?,
        );

        let provider = Self {
            auth_url: auth_url.to_string(),
            token_url: token_url.to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            client,
            state_store: Arc::new(RwLock::new(HashMap::new())),
        };

        // Ensure the provider exists in the database
        provider.ensure_provider_exists(db).await?;

        info!("GitHub OAuth provider initialized successfully");
        Ok(provider)
    }

    pub async fn generate_authorize_url(&self) -> (String, CsrfToken) {
        let (auth_url, csrf_token) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("user:email".to_string()))
            .url();

        // Store the CSRF token
        self.state_store
            .write()
            .await
            .insert(csrf_token.secret().clone(), csrf_token.clone());

        (auth_url.to_string(), csrf_token)
    }

    pub async fn validate_state(&self, state: &str) -> bool {
        self.state_store.read().await.contains_key(state)
    }

    pub async fn exchange_code(&self, code: String) -> Result<oauth2::AccessToken, Error> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| Error::OAuthError(format!("Failed to exchange code: {}", e)))?;

        Ok(token_result.access_token().clone())
    }

    async fn ensure_provider_exists(
        &self,
        db: Arc<dyn DBConnection + Send + Sync>,
    ) -> Result<(), Error> {
        debug!("Checking if GitHub OAuth provider exists in the database");
        let existing_provider = db.get_oauth_provider_by_name("github")?;

        if existing_provider.is_none() {
            info!("GitHub OAuth provider not found in database, creating new entry");
            let new_provider = NewOAuthProvider {
                name: "github".to_string(),
                auth_url: self.auth_url.clone(),
                token_url: self.token_url.clone(),
                user_info_url: self.user_info_url.clone(),
            };

            match db.create_oauth_provider(new_provider) {
                Ok(_) => info!("GitHub OAuth provider successfully added to database"),
                Err(e) => {
                    error!(
                        "Failed to create GitHub OAuth provider in database: {:?}",
                        e
                    );
                    return Err(e.into());
                }
            }
        } else {
            debug!("GitHub OAuth provider already exists in database");
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct GoogleProvider {
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub client: BasicClient,
    pub state_store: Arc<RwLock<HashMap<String, CsrfToken>>>,
}

impl GoogleProvider {
    pub async fn new(
        db: Arc<dyn DBConnection + Send + Sync>,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> Result<Self, Error> {
        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .map_err(|e| Error::OAuthError(format!("Invalid auth URL: {}", e)))?;
        let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
            .map_err(|e| Error::OAuthError(format!("Invalid token URL: {}", e)))?;

        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            auth_url.clone(),
            Some(token_url.clone()),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url)
                .map_err(|e| Error::OAuthError(format!("Invalid redirect URL: {}", e)))?,
        );

        let provider = Self {
            auth_url: auth_url.to_string(),
            token_url: token_url.to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v3/userinfo".to_string(),
            client,
            state_store: Arc::new(RwLock::new(HashMap::new())),
        };

        // Ensure the provider exists in the database
        provider.ensure_provider_exists(db).await?;

        info!("Google OAuth provider initialized successfully");
        Ok(provider)
    }

    pub async fn generate_authorize_url(&self) -> (String, CsrfToken) {
        let (auth_url, csrf_token) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();

        // Store the CSRF token
        self.state_store
            .write()
            .await
            .insert(csrf_token.secret().clone(), csrf_token.clone());

        (auth_url.to_string(), csrf_token)
    }

    pub async fn validate_state(&self, state: &str) -> bool {
        self.state_store.read().await.contains_key(state)
    }

    pub async fn exchange_code(&self, code: String) -> Result<oauth2::AccessToken, Error> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .request_async(oauth2::reqwest::async_http_client)
            .await
            .map_err(|e| Error::OAuthError(format!("Failed to exchange code: {}", e)))?;

        Ok(token_result.access_token().clone())
    }

    async fn ensure_provider_exists(
        &self,
        db: Arc<dyn DBConnection + Send + Sync>,
    ) -> Result<(), Error> {
        debug!("Checking if Google OAuth provider exists in the database");
        let existing_provider = db.get_oauth_provider_by_name("google")?;

        if existing_provider.is_none() {
            info!("Google OAuth provider not found in database, creating new entry");
            let new_provider = NewOAuthProvider {
                name: "google".to_string(),
                auth_url: self.auth_url.clone(),
                token_url: self.token_url.clone(),
                user_info_url: self.user_info_url.clone(),
            };

            match db.create_oauth_provider(new_provider) {
                Ok(_) => info!("Google OAuth provider successfully added to database"),
                Err(e) => {
                    error!(
                        "Failed to create Google OAuth provider in database: {:?}",
                        e
                    );
                    return Err(e.into());
                }
            }
        } else {
            debug!("Google OAuth provider already exists in database");
        }

        Ok(())
    }
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    async fn generate_authorize_url(&self) -> (String, CsrfToken);
    async fn validate_state(&self, state: &str) -> bool;
    async fn exchange_code(&self, code: String) -> Result<oauth2::AccessToken, Error>;
}

#[async_trait]
impl OAuthProvider for GithubProvider {
    async fn generate_authorize_url(&self) -> (String, CsrfToken) {
        self.generate_authorize_url().await
    }

    async fn validate_state(&self, state: &str) -> bool {
        self.validate_state(state).await
    }

    async fn exchange_code(&self, code: String) -> Result<oauth2::AccessToken, Error> {
        self.exchange_code(code).await
    }
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    async fn generate_authorize_url(&self) -> (String, CsrfToken) {
        self.generate_authorize_url().await
    }

    async fn validate_state(&self, state: &str) -> bool {
        self.validate_state(state).await
    }

    async fn exchange_code(&self, code: String) -> Result<oauth2::AccessToken, Error> {
        self.exchange_code(code).await
    }
}

pub struct OAuthManager {
    providers: HashMap<String, Box<dyn OAuthProvider + Send + Sync>>,
}

impl OAuthManager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn add_provider(&mut self, name: String, provider: Box<dyn OAuthProvider + Send + Sync>) {
        self.providers.insert(name, provider);
    }

    pub fn get_provider(&self, name: &str) -> Option<&(dyn OAuthProvider + Send + Sync)> {
        self.providers.get(name).map(|p| p.as_ref())
    }
}
