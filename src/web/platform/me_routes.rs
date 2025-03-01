use crate::{
    models::platform_users::PlatformUser,
    web::encryption_middleware::{decrypt_request, encrypt_response, EncryptedResponse},
    ApiError, AppState,
};
use axum::{extract::State, middleware::from_fn_with_state, routing::get, Extension, Json, Router};
use std::sync::Arc;
use tracing::{debug, error};
use uuid::Uuid;

use super::common::{MeResponse, OrgResponse, PlatformUserResponse};

pub fn router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/platform/me",
            get(get_platform_user)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .with_state(app_state)
}

async fn get_platform_user(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<MeResponse>>, ApiError> {
    debug!("Entering get_platform_user function");

    // Check if email is verified
    let email_verified = match data
        .db
        .get_platform_email_verification_by_platform_user_id(platform_user.uuid)
    {
        Ok(verification) => verification.is_verified,
        Err(crate::db::DBError::PlatformEmailVerificationNotFound) => false,
        Err(e) => {
            error!("Error fetching platform email verification: {:?}", e);
            return Err(ApiError::InternalServerError);
        }
    };

    // Get user's organization memberships
    let memberships = match data
        .db
        .get_all_org_memberships_for_platform_user(platform_user.uuid)
    {
        Ok(memberships) => memberships,
        Err(e) => {
            error!("Error fetching organization memberships: {:?}", e);
            return Err(ApiError::InternalServerError);
        }
    };

    // Create the list of organizations with roles
    let mut organizations = Vec::new();
    for membership in memberships {
        let org_id = membership.org_id;

        // Fetch the organization details
        let org = match data.db.get_org_by_id(org_id) {
            Ok(org) => org,
            Err(e) => {
                error!("Error fetching organization {}: {:?}", org_id, e);
                continue; // Skip this organization but continue processing others
            }
        };

        // Add to our list of organizations
        organizations.push(OrgResponse {
            id: org.uuid,
            name: org.name,
        });
    }

    // Create the platform user response object
    let user = PlatformUserResponse {
        id: platform_user.uuid,
        email: platform_user.email,
        name: platform_user.name,
        email_verified,
        created_at: platform_user.created_at,
        updated_at: platform_user.updated_at,
    };

    let response = MeResponse {
        user,
        organizations,
    };

    debug!("Exiting get_platform_user function");
    encrypt_response(&data, &session_id, &response).await
}

