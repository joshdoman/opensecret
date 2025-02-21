use crate::db::DBConnection;
use crate::models::oauth::NewOAuthProvider;
use crate::Error;
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthState {
    pub csrf_token: String,
    pub client_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct GithubProvider {
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub state_store: Arc<RwLock<HashMap<String, OAuthState>>>,
}

impl GithubProvider {
    pub async fn new(db: Arc<dyn DBConnection + Send + Sync>) -> Result<Self, Error> {
        let auth_url = "https://github.com/login/oauth/authorize".to_string();
        let token_url = "https://github.com/login/oauth/access_token".to_string();
        let user_info_url = "https://api.github.com/user".to_string();

        let provider = Self {
            auth_url,
            token_url,
            user_info_url,
            state_store: Arc::new(RwLock::new(HashMap::new())),
        };

        // Ensure the provider exists in the database
        provider.ensure_provider_exists(db).await?;

        info!("GitHub OAuth provider initialized successfully");
        Ok(provider)
    }

    pub async fn build_client(
        &self,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> Result<BasicClient, Error> {
        let auth_url = AuthUrl::new(self.auth_url.clone())
            .map_err(|e| Error::OAuthError(format!("Invalid auth URL: {}", e)))?;
        let token_url = TokenUrl::new(self.token_url.clone())
            .map_err(|e| Error::OAuthError(format!("Invalid token URL: {}", e)))?;

        Ok(BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url)
                .map_err(|e| Error::OAuthError(format!("Invalid redirect URL: {}", e)))?,
        ))
    }

    pub async fn generate_authorize_url(&self, client: &BasicClient) -> (String, CsrfToken) {
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("user:email".to_string()))
            .url();

        (auth_url.to_string(), csrf_token)
    }

    pub async fn store_state(&self, csrf_token: &str, state: OAuthState) {
        self.state_store
            .write()
            .await
            .insert(csrf_token.to_string(), state);
    }

    pub async fn validate_state(&self, state: &OAuthState) -> bool {
        if let Some(stored_state) = self.state_store.read().await.get(&state.csrf_token) {
            // Validate both the CSRF token and the client_id match
            stored_state == state
        } else {
            false
        }
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
    pub state_store: Arc<RwLock<HashMap<String, OAuthState>>>,
}

impl GoogleProvider {
    pub async fn new(db: Arc<dyn DBConnection + Send + Sync>) -> Result<Self, Error> {
        let auth_url = "https://accounts.google.com/o/oauth2/v2/auth".to_string();
        let token_url = "https://oauth2.googleapis.com/token".to_string();
        let user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo".to_string();

        let provider = Self {
            auth_url,
            token_url,
            user_info_url,
            state_store: Arc::new(RwLock::new(HashMap::new())),
        };

        // Ensure the provider exists in the database
        provider.ensure_provider_exists(db).await?;

        info!("Google OAuth provider initialized successfully");
        Ok(provider)
    }

    pub async fn build_client(
        &self,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> Result<BasicClient, Error> {
        let auth_url = AuthUrl::new(self.auth_url.clone())
            .map_err(|e| Error::OAuthError(format!("Invalid auth URL: {}", e)))?;
        let token_url = TokenUrl::new(self.token_url.clone())
            .map_err(|e| Error::OAuthError(format!("Invalid token URL: {}", e)))?;

        Ok(BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(
            RedirectUrl::new(redirect_url)
                .map_err(|e| Error::OAuthError(format!("Invalid redirect URL: {}", e)))?,
        ))
    }

    pub async fn generate_authorize_url(&self, client: &BasicClient) -> (String, CsrfToken) {
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();

        (auth_url.to_string(), csrf_token)
    }

    pub async fn store_state(&self, csrf_token: &str, state: OAuthState) {
        self.state_store
            .write()
            .await
            .insert(csrf_token.to_string(), state);
    }

    pub async fn validate_state(&self, state: &OAuthState) -> bool {
        if let Some(stored_state) = self.state_store.read().await.get(&state.csrf_token) {
            // Validate both the CSRF token and the client_id match
            stored_state == state
        } else {
            false
        }
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
pub trait OAuthProvider: Send + Sync + 'static {
    fn as_github(&self) -> Option<&GithubProvider> {
        None
    }

    fn as_google(&self) -> Option<&GoogleProvider> {
        None
    }

    async fn generate_authorize_url(&self, client: &BasicClient) -> (String, CsrfToken);
    async fn store_state(&self, csrf_token: &str, state: OAuthState);
    async fn validate_state(&self, state: &OAuthState) -> bool;
    async fn build_client(
        &self,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> Result<BasicClient, Error>;
}

pub struct OAuthManager {
    providers: HashMap<String, Box<dyn OAuthProvider>>,
}

impl OAuthManager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn add_provider(&mut self, name: String, provider: Box<dyn OAuthProvider>) {
        self.providers.insert(name, provider);
    }

    pub fn get_provider(&self, name: &str) -> Option<&dyn OAuthProvider> {
        self.providers.get(name).map(|p| p.as_ref())
    }
}

#[async_trait]
impl OAuthProvider for GithubProvider {
    fn as_github(&self) -> Option<&GithubProvider> {
        Some(self)
    }

    async fn generate_authorize_url(&self, client: &BasicClient) -> (String, CsrfToken) {
        self.generate_authorize_url(client).await
    }

    async fn store_state(&self, csrf_token: &str, state: OAuthState) {
        self.store_state(csrf_token, state).await
    }

    async fn validate_state(&self, state: &OAuthState) -> bool {
        self.validate_state(state).await
    }

    async fn build_client(
        &self,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> Result<BasicClient, Error> {
        self.build_client(client_id, client_secret, redirect_url)
            .await
    }
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    fn as_google(&self) -> Option<&GoogleProvider> {
        Some(self)
    }

    async fn generate_authorize_url(&self, client: &BasicClient) -> (String, CsrfToken) {
        self.generate_authorize_url(client).await
    }

    async fn store_state(&self, csrf_token: &str, state: OAuthState) {
        self.store_state(csrf_token, state).await
    }

    async fn validate_state(&self, state: &OAuthState) -> bool {
        self.validate_state(state).await
    }

    async fn build_client(
        &self,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> Result<BasicClient, Error> {
        self.build_client(client_id, client_secret, redirect_url)
            .await
    }
}
