use crate::AppState;
use axum::{http::StatusCode, Router};
use axum::{routing::get, Json};
use serde::Serialize;
use std::sync::Arc;

const API_VERSION: &str = "v1";

pub fn router_with_state(state: Arc<AppState>) -> Router<()> {
    Router::new()
        .route("/health-check", get(health_check))
        .with_state(state)
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Serialize)]
pub struct ExtendedHealthResponse {
    pub status: String,
    pub version: String,
    pub outbound_connectivity: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_check: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HealthResponse {
    /// Fabricate a status: pass response without checking database connectivity
    pub fn new_ok() -> Self {
        Self {
            status: String::from("pass"),
            version: String::from(API_VERSION),
        }
    }
}

/// Health check endpoint following the IETF draft standard
/// <https://datatracker.ietf.org/doc/html/draft-inadarei-api-health-check>
pub async fn health_check() -> Result<Json<HealthResponse>, (StatusCode, String)> {
    Ok(Json(HealthResponse::new_ok()))
}
