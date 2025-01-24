use crate::aws_credentials::AwsCredentialManager;
use aws_sdk_sqs::{config::Credentials, Client as SqsClient};
use backoff::SystemClock;
use backoff::{exponential::ExponentialBackoff, future::retry, Error as BackoffError};
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use uuid::Uuid;

const DEFAULT_REGION: &str = "us-east-2";
const INITIAL_INTERVAL_MS: u64 = 100;
const MAX_INTERVAL_MS: u64 = 10_000; // 10 seconds
const MAX_ELAPSED_TIME_SECS: u64 = 120; // 2 minutes

#[derive(Clone)]
pub struct SqsEventPublisher {
    queue_url: String,
    aws_credential_manager: Arc<RwLock<Option<AwsCredentialManager>>>,
    region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageEvent {
    pub event_id: Uuid,
    pub user_id: Uuid,
    pub input_tokens: i32,
    pub output_tokens: i32,
    pub estimated_cost: BigDecimal,
    pub chat_time: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum SqsError {
    #[error("AWS SDK error: {0}")]
    AwsSdk(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("No credentials available")]
    NoCredentials,
}

impl SqsEventPublisher {
    pub async fn new(
        queue_url: String,
        region: Option<String>,
        aws_credential_manager: Arc<RwLock<Option<AwsCredentialManager>>>,
    ) -> Self {
        let region = region.unwrap_or_else(|| DEFAULT_REGION.to_string());
        Self {
            queue_url,
            aws_credential_manager,
            region,
        }
    }

    async fn create_client(&self) -> Result<SqsClient, SqsError> {
        let creds = if let Some(manager) = self.aws_credential_manager.read().await.as_ref() {
            manager
                .get_credentials()
                .await
                .ok_or(SqsError::NoCredentials)?
        } else {
            debug!("Using default AWS credential chain");
            return Ok(SqsClient::new(
                &aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_types::region::Region::new(self.region.clone()))
                    .load()
                    .await,
            ));
        };

        let aws_creds = Credentials::new(
            creds.access_key_id,
            creds.secret_access_key,
            Some(creds.token),
            None,
            "sqs-publisher",
        );

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_types::region::Region::new(self.region.clone()))
            .credentials_provider(aws_creds)
            .load()
            .await;

        Ok(SqsClient::new(&config))
    }

    pub async fn publish_event(&self, event: UsageEvent) -> Result<(), SqsError> {
        let event_id = event.event_id;
        let user_id = event.user_id;

        info!("Publishing event {} for user {}", event_id, user_id);

        let backoff = ExponentialBackoff::<SystemClock> {
            initial_interval: Duration::from_millis(INITIAL_INTERVAL_MS),
            max_interval: Duration::from_millis(MAX_INTERVAL_MS),
            multiplier: 2.0,
            max_elapsed_time: Some(Duration::from_secs(MAX_ELAPSED_TIME_SECS)),
            ..ExponentialBackoff::default()
        };

        let result = retry(backoff, || async {
            let client = match self.create_client().await {
                Ok(client) => client,
                Err(e) => return Err(BackoffError::transient(e)),
            };

            let message_body = serde_json::to_string(&event)
                .map_err(|e| BackoffError::permanent(SqsError::Serialization(e)))?;

            debug!("sending message to SQS: {:?}", event);

            match client
                .send_message()
                .queue_url(&self.queue_url)
                .message_body(&message_body)
                .send()
                .await
            {
                Ok(_) => Ok(()),
                Err(e) => Err(BackoffError::transient(SqsError::AwsSdk(e.to_string()))),
            }
        })
        .await;

        match result {
            Ok(_) => {
                info!(
                    "Successfully published event {} for user {} to SQS",
                    event_id, user_id
                );
                Ok(())
            }
            Err(_) => {
                error!(
                    "Failed to publish event after retries. Event data: {:?}",
                    event
                );
                Err(SqsError::AwsSdk(
                    "Failed to publish after retries".to_string(),
                ))
            }
        }
    }
}
