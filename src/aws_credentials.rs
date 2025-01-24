use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::error;
use vsock::{VsockAddr, VsockStream};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AwsCredentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "Region")]
    pub region: String,
}

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
pub enum AwsCredentialError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Authentication error")]
    Authentication,

    #[error("Timed out waiting for credentials")]
    Timeout,
}

#[derive(Clone, Default)]
pub struct AwsCredentialManager {
    credentials: Arc<RwLock<Option<AwsCredentials>>>,
}

impl AwsCredentialManager {
    pub fn new() -> Self {
        Self {
            credentials: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn get_credentials(&self) -> Option<AwsCredentials> {
        let creds = self.credentials.read().await;
        creds.clone()
    }

    pub async fn set_credentials(&self, credentials: AwsCredentials) {
        let mut creds = self.credentials.write().await;
        *creds = Some(credentials);
    }

    pub async fn fetch_credentials(&self) -> Result<AwsCredentials, AwsCredentialError> {
        tracing::debug!("Entering fetch_credentials");

        let creds = Self::fetch_credentials_from_vsock().await?;
        self.set_credentials(creds.clone()).await;

        tracing::debug!("Exiting fetch_credentials");
        Ok(creds)
    }

    async fn fetch_credentials_from_vsock() -> Result<AwsCredentials, AwsCredentialError> {
        let cid = 3;
        let port = 8003;

        let sock_addr = VsockAddr::new(cid, port);
        let mut stream = VsockStream::connect(&sock_addr)?;

        let request = EnclaveRequest {
            request_type: "credentials".to_string(),
            key_name: None,
        };
        let request_json = serde_json::to_string(&request)?;
        stream.write_all(request_json.as_bytes())?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        let parent_response: ParentResponse = serde_json::from_str(&response)?;
        if parent_response.response_type == "credentials" {
            let creds: AwsCredentials = serde_json::from_value(parent_response.response_value)?;
            Ok(creds)
        } else {
            tracing::error!(
                "Failed to refresh AWS credentials: {:?}",
                AwsCredentialError::Authentication
            );
            Err(AwsCredentialError::Authentication)
        }
    }

    pub async fn wait_for_credentials(&self) -> AwsCredentials {
        tracing::info!("Waiting for initial AWS credentials");
        let max_retries = 12; // 1 minute total with 5s delay
        let mut attempts = 0;

        loop {
            match self.fetch_credentials().await {
                Ok(c) => return c,
                Err(e) => {
                    attempts += 1;
                    if attempts >= max_retries {
                        tracing::error!(
                            "Failed to get credentials after {} attempts, giving up",
                            max_retries
                        );
                        panic!("Could not obtain AWS credentials after maximum retries");
                    }
                    tracing::error!("Failed to refresh AWS credentials: {:?}", e);
                    tracing::info!(
                        "Retrying in 5 seconds... (attempt {}/{})",
                        attempts,
                        max_retries
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
}
