use crate::models::email_verification::{
    EmailVerification, EmailVerificationError, NewEmailVerification,
};
use crate::models::enclave_secrets::{EnclaveSecret, EnclaveSecretError, NewEnclaveSecret};
use crate::models::oauth::{
    NewOAuthProvider, NewUserOAuthConnection, OAuthError, OAuthProvider, UserOAuthConnection,
};
use crate::models::password_reset::{
    NewPasswordResetRequest, PasswordResetError, PasswordResetRequest,
};
use crate::models::token_usage::{NewTokenUsage, TokenUsage, TokenUsageError};
use crate::models::users::{NewUser, User, UserError};
use diesel::{
    pg::PgConnection,
    r2d2::{ConnectionManager, Pool},
};
use std::sync::Arc;
use tracing::{debug, error, info};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum DBError {
    #[error("Database connection error")]
    ConnectionError,
    #[error("Database query error: {0}")]
    QueryError(#[from] diesel::result::Error),
    #[error("User error: {0}")]
    UserError(#[from] UserError),
    #[error("User not found")]
    UserNotFound,
    #[error("Enclave secret error: {0}")]
    EnclaveSecretError(#[from] EnclaveSecretError),
    #[error("Email verification error: {0}")]
    EmailVerificationError(#[from] EmailVerificationError),
    #[error("Email verification not found")]
    EmailVerificationNotFound,
    #[error("Password reset error: {0}")]
    PasswordResetError(#[from] PasswordResetError),
    #[error("Password reset request not found")]
    PasswordResetRequestNotFound,
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] crate::encrypt::EncryptError),
    #[error("OAuth error: {0}")]
    OAuthError(#[from] OAuthError),
    #[error("Token usage error: {0}")]
    TokenUsageError(#[from] TokenUsageError),
}

#[allow(dead_code)]
pub trait DBConnection {
    fn create_user(&self, new_user: NewUser) -> Result<User, DBError>;
    fn get_user_by_uuid(&self, uuid: Uuid) -> Result<User, DBError>;
    fn get_user_by_email(&self, email: String) -> Result<User, DBError>;
    fn set_user_key(&self, user: User, private_key: Vec<u8>) -> Result<(), DBError>;
    fn get_pool(&self) -> &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>>;
    fn create_enclave_secret(&self, new_secret: NewEnclaveSecret)
        -> Result<EnclaveSecret, DBError>;
    fn get_enclave_secret_by_id(&self, id: i32) -> Result<Option<EnclaveSecret>, DBError>;
    fn get_enclave_secret_by_key(&self, key: &str) -> Result<Option<EnclaveSecret>, DBError>;
    fn get_all_enclave_secrets(&self) -> Result<Vec<EnclaveSecret>, DBError>;
    fn update_enclave_secret(&self, secret: &EnclaveSecret) -> Result<(), DBError>;
    fn delete_enclave_secret(&self, secret: &EnclaveSecret) -> Result<(), DBError>;
    fn create_email_verification(
        &self,
        new_verification: NewEmailVerification,
    ) -> Result<EmailVerification, DBError>;
    fn get_email_verification_by_id(&self, id: i32) -> Result<EmailVerification, DBError>;
    fn get_email_verification_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<EmailVerification, DBError>;
    fn get_email_verification_by_code(&self, code: Uuid) -> Result<EmailVerification, DBError>;
    fn update_email_verification(&self, verification: &EmailVerification) -> Result<(), DBError>;
    fn delete_email_verification(&self, verification: &EmailVerification) -> Result<(), DBError>;
    fn verify_email(&self, verification: &mut EmailVerification) -> Result<(), DBError>;
    fn create_password_reset_request(
        &self,
        new_request: NewPasswordResetRequest,
    ) -> Result<PasswordResetRequest, DBError>;
    fn get_password_reset_request_by_user_id_and_code(
        &self,
        user_id: Uuid,
        encrypted_code: Vec<u8>,
    ) -> Result<Option<PasswordResetRequest>, DBError>;
    fn update_user_password(
        &self,
        user: &User,
        new_password_enc: Option<Vec<u8>>,
    ) -> Result<(), DBError>;
    fn mark_password_reset_as_complete(
        &self,
        request: &PasswordResetRequest,
    ) -> Result<(), DBError>;

    // OAuth Provider methods
    fn create_oauth_provider(
        &self,
        new_provider: NewOAuthProvider,
    ) -> Result<OAuthProvider, DBError>;
    fn get_oauth_provider_by_id(&self, id: i32) -> Result<Option<OAuthProvider>, DBError>;
    fn get_oauth_provider_by_name(&self, name: &str) -> Result<Option<OAuthProvider>, DBError>;
    fn get_all_oauth_providers(&self) -> Result<Vec<OAuthProvider>, DBError>;
    fn update_oauth_provider(&self, provider: &OAuthProvider) -> Result<(), DBError>;
    fn delete_oauth_provider(&self, provider: &OAuthProvider) -> Result<(), DBError>;

    // User OAuth Connection methods
    fn create_user_oauth_connection(
        &self,
        new_connection: NewUserOAuthConnection,
    ) -> Result<UserOAuthConnection, DBError>;
    fn get_user_oauth_connection_by_id(
        &self,
        id: i32,
    ) -> Result<Option<UserOAuthConnection>, DBError>;
    fn get_user_oauth_connection_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider_id: i32,
    ) -> Result<Option<UserOAuthConnection>, DBError>;
    fn get_all_user_oauth_connections_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserOAuthConnection>, DBError>;
    fn update_user_oauth_connection(&self, connection: &UserOAuthConnection)
        -> Result<(), DBError>;
    fn delete_user_oauth_connection(&self, connection: &UserOAuthConnection)
        -> Result<(), DBError>;

    fn create_token_usage(&self, new_usage: NewTokenUsage) -> Result<TokenUsage, DBError>;

    fn update_user(&self, user: &User) -> Result<(), DBError>;
}

pub(crate) struct PostgresConnection {
    db: Pool<ConnectionManager<PgConnection>>,
}

impl DBConnection for PostgresConnection {
    fn create_user(&self, new_user: NewUser) -> Result<User, DBError> {
        debug!("Creating new user");
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        let result = new_user.insert(conn).map_err(DBError::from);
        if let Err(ref e) = result {
            error!("Failed to create user: {:?}", e);
        }
        result
    }

    fn get_user_by_uuid(&self, uuid: Uuid) -> Result<User, DBError> {
        debug!("Getting user by UUID");
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        let result = User::get_by_uuid(conn, uuid)?.ok_or(DBError::UserNotFound);
        if let Err(ref e) = result {
            error!("Failed to get user by UUID: {:?}", e);
        }
        result
    }

    fn get_user_by_email(&self, email: String) -> Result<User, DBError> {
        debug!("Getting user by email");
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        let result = User::get_by_email(conn, email)?.ok_or(DBError::UserNotFound);
        if let Err(ref e) = result {
            error!("Failed to get user by email: {:?}", e);
        }
        result
    }

    fn set_user_key(&self, user: User, private_key: Vec<u8>) -> Result<(), DBError> {
        debug!("Setting user key");
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        let result = user.set_key(conn, private_key).map_err(DBError::from);
        if let Err(ref e) = result {
            error!("Failed to set user key: {:?}", e);
        }
        result
    }

    fn get_pool(&self) -> &diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<PgConnection>> {
        &self.db
    }

    fn create_enclave_secret(
        &self,
        new_secret: NewEnclaveSecret,
    ) -> Result<EnclaveSecret, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        new_secret.insert(conn).map_err(DBError::from)
    }

    fn get_enclave_secret_by_id(&self, id: i32) -> Result<Option<EnclaveSecret>, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        EnclaveSecret::get_by_id(conn, id).map_err(DBError::from)
    }

    fn get_enclave_secret_by_key(&self, key: &str) -> Result<Option<EnclaveSecret>, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        EnclaveSecret::get_by_key(conn, key).map_err(DBError::from)
    }

    fn get_all_enclave_secrets(&self) -> Result<Vec<EnclaveSecret>, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        EnclaveSecret::get_all(conn).map_err(DBError::from)
    }

    fn update_enclave_secret(&self, secret: &EnclaveSecret) -> Result<(), DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        secret.update(conn).map_err(DBError::from)
    }

    fn delete_enclave_secret(&self, secret: &EnclaveSecret) -> Result<(), DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        secret.delete(conn).map_err(DBError::from)
    }

    fn create_email_verification(
        &self,
        new_verification: NewEmailVerification,
    ) -> Result<EmailVerification, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        new_verification.insert(conn).map_err(DBError::from)
    }

    fn get_email_verification_by_id(&self, id: i32) -> Result<EmailVerification, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        EmailVerification::get_by_id(conn, id)?.ok_or(DBError::EmailVerificationNotFound)
    }

    fn get_email_verification_by_user_id(
        &self,
        user_id: Uuid,
    ) -> Result<EmailVerification, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        EmailVerification::get_by_user_id(conn, user_id)?.ok_or(DBError::EmailVerificationNotFound)
    }

    fn get_email_verification_by_code(&self, code: Uuid) -> Result<EmailVerification, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        EmailVerification::get_by_verification_code(conn, code)?
            .ok_or(DBError::EmailVerificationNotFound)
    }

    fn update_email_verification(&self, verification: &EmailVerification) -> Result<(), DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        verification.update(conn).map_err(DBError::from)
    }

    fn delete_email_verification(&self, verification: &EmailVerification) -> Result<(), DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        verification.delete(conn).map_err(DBError::from)
    }

    fn verify_email(&self, verification: &mut EmailVerification) -> Result<(), DBError> {
        debug!("Verifying email");
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        let result = verification.verify(conn).map_err(DBError::from);
        if let Err(ref e) = result {
            error!("Failed to verify email: {:?}", e);
        }
        result
    }

    fn create_password_reset_request(
        &self,
        new_request: NewPasswordResetRequest,
    ) -> Result<PasswordResetRequest, DBError> {
        debug!("Creating new password reset request");
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        let result = new_request.insert(conn).map_err(DBError::from);
        if let Err(ref e) = result {
            error!("Failed to create password reset request: {:?}", e);
        }
        result
    }

    fn get_password_reset_request_by_user_id_and_code(
        &self,
        user_id: Uuid,
        encrypted_code: Vec<u8>,
    ) -> Result<Option<PasswordResetRequest>, DBError> {
        debug!("Getting password reset request by user_id and encrypted code");
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        let result = PasswordResetRequest::get_by_user_id_and_code(conn, user_id, &encrypted_code)
            .map_err(DBError::from);
        if let Err(ref e) = result {
            error!("Failed to get password reset request: {:?}", e);
        }
        result
    }

    fn update_user_password(
        &self,
        user: &User,
        new_password_enc: Option<Vec<u8>>,
    ) -> Result<(), DBError> {
        debug!("Updating user password");
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        let result = user
            .update_password(conn, new_password_enc)
            .map_err(DBError::from);
        if let Err(ref e) = result {
            error!("Failed to update user password: {:?}", e);
        }
        result
    }

    fn mark_password_reset_as_complete(
        &self,
        request: &PasswordResetRequest,
    ) -> Result<(), DBError> {
        debug!("Marking password reset request as complete");
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        let result = request.mark_as_reset(conn).map_err(DBError::from);
        if let Err(ref e) = result {
            error!("Failed to mark password reset request as complete: {:?}", e);
        }
        result
    }

    // OAuth Provider method implementations
    fn create_oauth_provider(
        &self,
        new_provider: NewOAuthProvider,
    ) -> Result<OAuthProvider, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        new_provider.insert(conn).map_err(DBError::from)
    }

    fn get_oauth_provider_by_id(&self, id: i32) -> Result<Option<OAuthProvider>, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        OAuthProvider::get_by_id(conn, id).map_err(DBError::from)
    }

    fn get_oauth_provider_by_name(&self, name: &str) -> Result<Option<OAuthProvider>, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        OAuthProvider::get_by_name(conn, name).map_err(DBError::from)
    }

    fn get_all_oauth_providers(&self) -> Result<Vec<OAuthProvider>, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        OAuthProvider::get_all(conn).map_err(DBError::from)
    }

    fn update_oauth_provider(&self, provider: &OAuthProvider) -> Result<(), DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        provider.update(conn).map_err(DBError::from)
    }

    fn delete_oauth_provider(&self, provider: &OAuthProvider) -> Result<(), DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        provider.delete(conn).map_err(DBError::from)
    }

    // User OAuth Connection method implementations
    fn create_user_oauth_connection(
        &self,
        new_connection: NewUserOAuthConnection,
    ) -> Result<UserOAuthConnection, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        new_connection.insert(conn).map_err(DBError::from)
    }

    fn get_user_oauth_connection_by_id(
        &self,
        id: i32,
    ) -> Result<Option<UserOAuthConnection>, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        UserOAuthConnection::get_by_id(conn, id).map_err(DBError::from)
    }

    fn get_user_oauth_connection_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider_id: i32,
    ) -> Result<Option<UserOAuthConnection>, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        UserOAuthConnection::get_by_user_and_provider(conn, user_id, provider_id)
            .map_err(DBError::from)
    }

    fn get_all_user_oauth_connections_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserOAuthConnection>, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        UserOAuthConnection::get_all_for_user(conn, user_id).map_err(DBError::from)
    }

    fn update_user_oauth_connection(
        &self,
        connection: &UserOAuthConnection,
    ) -> Result<(), DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        connection.update(conn).map_err(DBError::from)
    }

    fn delete_user_oauth_connection(
        &self,
        connection: &UserOAuthConnection,
    ) -> Result<(), DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        connection.delete(conn).map_err(DBError::from)
    }

    fn create_token_usage(&self, new_usage: NewTokenUsage) -> Result<TokenUsage, DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        new_usage.insert(conn).map_err(DBError::from)
    }

    fn update_user(&self, user: &User) -> Result<(), DBError> {
        let conn = &mut self.db.get().map_err(|_| DBError::ConnectionError)?;
        user.update(conn).map_err(DBError::from)
    }
}

pub(crate) fn setup_db(url: String) -> Arc<dyn DBConnection + Send + Sync> {
    info!("Connecting to database...");
    let manager = ConnectionManager::<PgConnection>::new(url);
    // TODO make pool size bigger, just for testing connection issues
    let pool = Pool::builder()
        .max_size(1) // should be a multiple of 100, our database connection limit
        .test_on_check_out(true)
        .build(manager)
        .expect("Unable to build DB connection pool");
    info!("Connected to database");
    Arc::new(PostgresConnection { db: pool })
}
