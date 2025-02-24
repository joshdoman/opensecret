use crate::models::invite_codes::InviteCodeError;
use crate::models::org_memberships::OrgMembershipError;
use crate::models::org_project_secrets::NewOrgProjectSecret;
use crate::models::project_settings::EmailSettings;
use crate::models::project_settings::OAuthProviderSettings;
use crate::models::project_settings::OAuthSettings;
use crate::models::project_settings::SettingCategory;
use crate::DBError;
use crate::{
    email::send_platform_invite_email,
    models::{
        invite_codes::NewInviteCode,
        org_memberships::{NewOrgMembership, OrgRole},
        org_projects::NewOrgProject,
        orgs::NewOrg,
        platform_users::PlatformUser,
    },
    web::encryption_middleware::{decrypt_request, encrypt_response, EncryptedResponse},
    web::platform::validation::{
        validate_alphanumeric_only, validate_alphanumeric_with_symbols, validate_secret_size,
    },
    ApiError, AppState,
};
use axum::routing::put;
use axum::{
    extract::{Path, State},
    middleware::from_fn_with_state,
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use base64::engine::general_purpose;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::spawn;
use tracing::{debug, error};
use uuid::Uuid;
use validator::Validate;

pub const PROJECT_RESEND_API_KEY: &str = "RESEND_API_KEY";
pub const PROJECT_GOOGLE_OAUTH_SECRET: &str = "GOOGLE_OAUTH_SECRET";
pub const PROJECT_GITHUB_OAUTH_SECRET: &str = "GITHUB_OAUTH_SECRET";

#[derive(Deserialize, Clone, Validate)]
pub struct CreateOrgRequest {
    #[validate(length(min = 1, max = 50))]
    #[validate(custom(function = "validate_alphanumeric_with_symbols"))]
    pub name: String,
}

#[derive(Deserialize, Clone, Validate)]
pub struct CreateProjectRequest {
    #[validate(length(min = 1, max = 50))]
    #[validate(custom(function = "validate_alphanumeric_with_symbols"))]
    pub name: String,
    #[validate(length(max = 255))]
    pub description: Option<String>,
}

#[derive(Deserialize, Clone, Validate)]
pub struct UpdateProjectRequest {
    #[validate(length(min = 1, max = 50))]
    #[validate(custom(function = "validate_alphanumeric_with_symbols"))]
    pub name: Option<String>,
    #[validate(length(max = 255))]
    pub description: Option<String>,
    #[validate(custom(function = "validate_project_status"))]
    pub status: Option<String>,
}

fn validate_project_status(status: &str) -> Result<(), validator::ValidationError> {
    match status {
        "active" | "inactive" | "suspended" => Ok(()),
        _ => Err(validator::ValidationError::new("project_status")),
    }
}

#[derive(Deserialize, Clone, Validate)]
pub struct CreateInviteRequest {
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(max = 255, message = "Email must not exceed 255 characters"))]
    pub email: String,
    #[serde(default = "default_invite_role")]
    pub role: OrgRole,
}

fn default_invite_role() -> OrgRole {
    OrgRole::Admin
}

#[derive(Deserialize, Clone, Validate)]
pub struct UpdateMembershipRequest {
    pub role: OrgRole,
}

#[derive(Deserialize, Clone, Validate)]
pub struct CreateSecretRequest {
    #[validate(length(min = 1, max = 50))]
    #[validate(custom(function = "validate_alphanumeric_only"))]
    pub key_name: String,
    #[validate(custom(function = "validate_secret_size"))]
    pub secret: String, // Base64 encoded secret value
}

#[derive(Serialize)]
pub struct OrgResponse {
    pub id: Uuid,
    pub name: String,
}

#[derive(Serialize)]
pub struct ProjectResponse {
    pub id: Uuid,
    pub client_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
}

#[derive(Serialize)]
pub struct MembershipResponse {
    pub user_id: Uuid,
    pub role: String,
}

#[derive(Serialize)]
pub struct InviteResponse {
    pub code: Uuid,
}

#[derive(Serialize)]
pub struct SecretResponse {
    pub key_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ProjectSettingResponse {
    pub category: String,
    pub settings: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Deserialize, Clone, Validate)]
pub struct UpdateProjectSettingsRequest {
    pub settings: serde_json::Value,
}

#[derive(Deserialize, Clone, Validate)]
pub struct UpdateEmailSettingsRequest {
    #[validate(length(min = 1, max = 255))]
    pub provider: String,
    #[validate(email)]
    pub send_from: String,
    pub email_verification_url: String,
}

#[derive(Deserialize, Clone, Validate)]
pub struct UpdateOAuthSettingsRequest {
    pub google_oauth_enabled: bool,
    pub github_oauth_enabled: bool,
    #[validate(custom(function = "validate_oauth_provider_settings"))]
    pub google_oauth_settings: Option<OAuthProviderSettings>,
    #[validate(custom(function = "validate_oauth_provider_settings"))]
    pub github_oauth_settings: Option<OAuthProviderSettings>,
}

fn validate_oauth_provider_settings(
    settings: &&OAuthProviderSettings,
) -> Result<(), validator::ValidationError> {
    // Validate client_id
    if settings.client_id.is_empty() || settings.client_id.len() > 255 {
        return Err(validator::ValidationError::new("oauth_client_id"));
    }
    // Validate redirect_url
    if settings.redirect_url.is_empty() || settings.redirect_url.len() > 255 {
        return Err(validator::ValidationError::new("oauth_redirect_url"));
    }
    // Basic URL validation
    if url::Url::parse(&settings.redirect_url).is_err() {
        return Err(validator::ValidationError::new(
            "oauth_redirect_url_invalid",
        ));
    }
    Ok(())
}

pub fn router(app_state: Arc<AppState>) -> Router {
    Router::new()
        // Organization routes
        .route(
            "/platform/orgs",
            post(create_org).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<CreateOrgRequest>,
            )),
        )
        .route(
            "/platform/orgs",
            get(list_orgs).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/platform/orgs/:org_id",
            delete(delete_org).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        // Project routes
        .route(
            "/platform/orgs/:org_id/projects",
            post(create_project).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<CreateProjectRequest>,
            )),
        )
        .route(
            "/platform/orgs/:org_id/projects",
            get(list_projects).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id",
            patch(update_project).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<UpdateProjectRequest>,
            )),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id",
            delete(delete_project)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id/secrets",
            post(create_secret).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<CreateSecretRequest>,
            )),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id/secrets",
            get(list_secrets).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id/secrets/:key_name",
            delete(delete_secret)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        // Project settings routes
        .route(
            "/platform/orgs/:org_id/projects/:project_id/settings/:category",
            get(get_project_settings)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id/settings/:category",
            put(update_project_settings).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<UpdateProjectSettingsRequest>,
            )),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id/settings/email",
            get(get_email_settings)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id/settings/email",
            put(update_email_settings).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<UpdateEmailSettingsRequest>,
            )),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id/settings/oauth",
            get(get_oauth_settings)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/platform/orgs/:org_id/projects/:project_id/settings/oauth",
            put(update_oauth_settings).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<UpdateOAuthSettingsRequest>,
            )),
        )
        // Membership and invite routes
        .route(
            "/platform/orgs/:org_id/invites",
            post(create_invite).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<CreateInviteRequest>,
            )),
        )
        .route(
            "/platform/orgs/:org_id/memberships",
            get(list_memberships)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/platform/orgs/:org_id/memberships/:user_id",
            patch(update_membership).layer(from_fn_with_state(
                app_state.clone(),
                decrypt_request::<UpdateMembershipRequest>,
            )),
        )
        .route(
            "/platform/orgs/:org_id/memberships/:user_id",
            delete(delete_membership)
                .layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .route(
            "/platform/accept_invite/:code",
            post(accept_invite).layer(from_fn_with_state(app_state.clone(), decrypt_request::<()>)),
        )
        .with_state(app_state)
}

async fn create_org(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Extension(create_request): Extension<CreateOrgRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<OrgResponse>>, ApiError> {
    debug!("Creating new organization");

    // Validate request
    if let Err(errors) = create_request.validate() {
        error!("Validation error: {:?}", errors);
        return Err(ApiError::BadRequest);
    }

    // Create the organization and owner membership in a single transaction
    let new_org = NewOrg::new(create_request.name);
    let org = data
        .db
        .create_org_with_owner(new_org, platform_user.uuid)
        .map_err(|e| {
            error!("Failed to create organization with owner: {:?}", e);
            ApiError::InternalServerError
        })?;

    let response = OrgResponse {
        id: org.uuid,
        name: org.name,
    };

    encrypt_response(&data, &session_id, &response).await
}

async fn list_orgs(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<Vec<OrgResponse>>>, ApiError> {
    debug!("Listing organizations");

    // Get all memberships for the user
    let memberships = data
        .db
        .get_all_org_memberships_for_platform_user(platform_user.uuid)
        .map_err(|e| {
            error!("Failed to get org memberships: {:?}", e);
            ApiError::InternalServerError
        })?;

    // Get org details for each membership
    let mut orgs = Vec::new();
    for membership in memberships {
        match data.db.get_org_by_id(membership.org_id) {
            Ok(org) => {
                orgs.push(OrgResponse {
                    id: org.uuid,
                    name: org.name,
                });
            }
            Err(e) => {
                error!(
                    "Failed to get org details for org_id {}: {:?}",
                    membership.org_id, e
                );
                // Continue with the next membership
            }
        }
    }

    encrypt_response(&data, &session_id, &orgs).await
}

async fn delete_org(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path(org_id): Path<Uuid>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<serde_json::Value>>, ApiError> {
    debug!("Deleting organization");

    // Get org by UUID instead of ID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    // Verify user has owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    if membership.role != OrgRole::Owner.as_str() {
        return Err(ApiError::Unauthorized);
    }

    // Delete the org
    data.db.delete_org(&org).map_err(|e| {
        error!("Failed to delete organization: {:?}", e);
        ApiError::InternalServerError
    })?;

    let response = serde_json::json!({
        "message": "Organization deleted successfully"
    });

    encrypt_response(&data, &session_id, &response).await
}

async fn create_project(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path(org_id): Path<Uuid>,
    Extension(create_request): Extension<CreateProjectRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<ProjectResponse>>, ApiError> {
    debug!("Creating new project");

    // Validate request
    if let Err(errors) = create_request.validate() {
        error!("Validation error: {:?}", errors);
        return Err(ApiError::BadRequest);
    }

    // Get org by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    // Verify user has admin or owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    let role: OrgRole = membership.role.into();
    if !matches!(role, OrgRole::Owner | OrgRole::Admin) {
        return Err(ApiError::Unauthorized);
    }

    // Create the project
    let new_project = NewOrgProject::new(org.id, create_request.name).with_description(
        create_request
            .description
            .unwrap_or_else(|| String::from("")),
    );

    let project = data.db.create_org_project(new_project).map_err(|e| {
        error!("Failed to create project: {:?}", e);
        ApiError::InternalServerError
    })?;

    let response = ProjectResponse {
        id: project.uuid,
        client_id: project.client_id,
        name: project.name,
        description: project.description,
        status: project.status,
    };

    encrypt_response(&data, &session_id, &response).await
}

async fn list_projects(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path(org_id): Path<Uuid>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<Vec<ProjectResponse>>>, ApiError> {
    debug!("Listing projects");

    // Get org by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    // Verify user has any role in the org
    let _membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    // Get all projects
    let projects = data.db.get_all_org_projects_for_org(org.id).map_err(|e| {
        error!("Failed to get projects: {:?}", e);
        ApiError::InternalServerError
    })?;

    let response = projects
        .into_iter()
        .map(|p| ProjectResponse {
            id: p.uuid,
            client_id: p.client_id,
            name: p.name,
            description: p.description,
            status: p.status,
        })
        .collect();

    encrypt_response(&data, &session_id, &response).await
}

async fn update_project(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id)): Path<(Uuid, Uuid)>,
    Extension(update_request): Extension<UpdateProjectRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<ProjectResponse>>, ApiError> {
    debug!("Updating project");

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data
        .db
        .get_org_project_by_uuid(project_id)
        .map_err(|_| ApiError::NotFound)?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        return Err(ApiError::NotFound);
    }

    // Verify user has admin or owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    let role: OrgRole = membership.role.into();
    if !matches!(role, OrgRole::Owner | OrgRole::Admin) {
        return Err(ApiError::Unauthorized);
    }

    // Update the project
    let mut updated_project = project;
    if let Some(name) = update_request.name {
        updated_project.name = name;
    }
    if let Some(description) = update_request.description {
        updated_project.description = Some(description);
    }
    if let Some(status) = update_request.status {
        updated_project.status = status;
    }

    data.db.update_org_project(&updated_project).map_err(|e| {
        error!("Failed to update project: {:?}", e);
        ApiError::InternalServerError
    })?;

    let response = ProjectResponse {
        id: updated_project.uuid,
        client_id: updated_project.client_id,
        name: updated_project.name,
        description: updated_project.description,
        status: updated_project.status,
    };

    encrypt_response(&data, &session_id, &response).await
}

async fn delete_project(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id)): Path<(Uuid, Uuid)>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<serde_json::Value>>, ApiError> {
    debug!("Deleting project");

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data
        .db
        .get_org_project_by_uuid(project_id)
        .map_err(|_| ApiError::NotFound)?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        return Err(ApiError::NotFound);
    }

    // Verify user has admin or owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    let role: OrgRole = membership.role.into();
    if !matches!(role, OrgRole::Owner | OrgRole::Admin) {
        return Err(ApiError::Unauthorized);
    }

    // Delete the project
    data.db.delete_org_project(&project).map_err(|e| {
        error!("Failed to delete project: {:?}", e);
        ApiError::InternalServerError
    })?;

    let response = serde_json::json!({
        "message": "Project deleted successfully"
    });

    encrypt_response(&data, &session_id, &response).await
}

async fn create_invite(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path(org_id): Path<Uuid>,
    Extension(create_request): Extension<CreateInviteRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<InviteResponse>>, ApiError> {
    debug!("Creating invite");

    // Get the org by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::BadRequest)?;

    // Verify user has admin or owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    let role: OrgRole = membership.role.into();
    if !matches!(role, OrgRole::Owner | OrgRole::Admin) {
        return Err(ApiError::Unauthorized);
    }

    // Create the invite code with the specified role (or default admin)
    let new_invite = NewInviteCode::new(
        org.id,
        create_request.email.clone(),
        create_request.role.as_str().to_string(),
        24, // 24 hour expiry
    );

    let invite = data.db.create_invite_code(new_invite).map_err(|e| {
        error!("Failed to create invite code: {:?}", e);
        ApiError::InternalServerError
    })?;

    // Send invite email in background
    let email = create_request.email;
    let invite_code = invite.code;
    let app_mode = data.app_mode.clone();
    let resend_api_key = data.resend_api_key.clone();
    spawn(async move {
        if let Err(e) =
            send_platform_invite_email(app_mode, resend_api_key, email, org.name, invite_code).await
        {
            error!("Failed to send invite email: {:?}", e);
        }
    });

    let response = InviteResponse { code: invite.code };

    encrypt_response(&data, &session_id, &response).await
}

async fn list_memberships(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path(org_id): Path<Uuid>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<Vec<MembershipResponse>>>, ApiError> {
    debug!("Listing memberships");

    // Get the org by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    // Verify user has any role in the org
    let _membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    // Get all memberships
    let memberships = data
        .db
        .get_all_org_memberships_for_org(org.id)
        .map_err(|e| {
            error!("Failed to get memberships: {:?}", e);
            ApiError::InternalServerError
        })?;

    let response = memberships
        .into_iter()
        .map(|m| MembershipResponse {
            user_id: m.platform_user_id,
            role: m.role,
        })
        .collect();

    encrypt_response(&data, &session_id, &response).await
}

async fn update_membership(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
    Extension(update_request): Extension<UpdateMembershipRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<MembershipResponse>>, ApiError> {
    debug!("Updating membership");

    // Get the org by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    // Verify user has owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    if membership.role != OrgRole::Owner.as_str() {
        return Err(ApiError::Unauthorized);
    }

    // Get and update the target membership
    let mut target_membership = data
        .db
        .get_org_membership_by_platform_user_and_org(user_id, org.id)
        .map_err(|_| ApiError::NotFound)?;

    // Update role with transactional owner check
    data.db
        .update_membership_role(&mut target_membership, update_request.role)
        .map_err(|e| match e {
            DBError::OrgMembershipError(OrgMembershipError::DatabaseError(
                diesel::result::Error::RollbackTransaction,
            )) => {
                error!("Cannot demote the last owner of the organization");
                ApiError::BadRequest
            }
            _ => {
                error!("Failed to update membership: {:?}", e);
                ApiError::InternalServerError
            }
        })?;

    let response = MembershipResponse {
        user_id: target_membership.platform_user_id,
        role: target_membership.role,
    };

    encrypt_response(&data, &session_id, &response).await
}

async fn delete_membership(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<serde_json::Value>>, ApiError> {
    debug!("Deleting membership");

    // Get the org by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    // Verify user has owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    if membership.role != OrgRole::Owner.as_str() {
        return Err(ApiError::Unauthorized);
    }

    // Get the target membership
    let target_membership = data
        .db
        .get_org_membership_by_platform_user_and_org(user_id, org.id)
        .map_err(|_| ApiError::NotFound)?;

    // Delete with transactional owner check
    data.db
        .delete_membership_with_owner_check(&target_membership)
        .map_err(|e| match e {
            DBError::OrgMembershipError(OrgMembershipError::DatabaseError(
                diesel::result::Error::RollbackTransaction,
            )) => {
                error!("Cannot delete the last owner of the organization");
                ApiError::BadRequest
            }
            _ => {
                error!("Failed to delete membership: {:?}", e);
                ApiError::InternalServerError
            }
        })?;

    let response = serde_json::json!({
        "message": "Membership deleted successfully"
    });

    encrypt_response(&data, &session_id, &response).await
}

async fn accept_invite(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path(code): Path<Uuid>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<serde_json::Value>>, ApiError> {
    debug!("Accepting invite");

    // Get and validate the invite code
    let invite = data
        .db
        .get_invite_code_by_code(code)
        .map_err(|_| ApiError::NotFound)?;

    if invite.used {
        return Err(ApiError::BadRequest);
    }

    if invite.expires_at < chrono::Utc::now() {
        return Err(ApiError::BadRequest);
    }

    if invite.email != platform_user.email {
        return Err(ApiError::Unauthorized);
    }

    // Create the membership and mark invite as used in a single transaction
    let new_membership = NewOrgMembership::new(
        platform_user.uuid,
        invite.org_id,
        invite.role.clone().into(),
    );
    data.db
        .accept_invite_transaction(&invite, new_membership)
        .map_err(|e| {
            error!("Failed to accept invite: {:?}", e);
            match e {
                DBError::InviteCodeError(InviteCodeError::AlreadyUsed) => ApiError::BadRequest,
                DBError::InviteCodeError(InviteCodeError::Expired) => ApiError::BadRequest,
                _ => ApiError::InternalServerError,
            }
        })?;

    let response = serde_json::json!({
        "message": "Invite accepted successfully"
    });

    encrypt_response(&data, &session_id, &response).await
}

pub async fn create_secret(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id)): Path<(Uuid, Uuid)>,
    Extension(create_request): Extension<CreateSecretRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<SecretResponse>>, ApiError> {
    debug!("Creating project secret");

    // Validate request
    if let Err(errors) = create_request.validate() {
        error!("Validation error: {:?}", errors);
        return Err(ApiError::BadRequest);
    }

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data.db.get_org_project_by_uuid(project_id).map_err(|_| {
        error!("Project not found");
        ApiError::NotFound
    })?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        error!("Project does not belong to organization");
        return Err(ApiError::NotFound);
    }

    // Verify user has admin or owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    let role: OrgRole = membership.role.into();
    if !matches!(role, OrgRole::Owner | OrgRole::Admin) {
        return Err(ApiError::Unauthorized);
    }

    // Decode base64 secret value to raw bytes
    let secret_bytes = general_purpose::STANDARD
        .decode(&create_request.secret)
        .map_err(|e| {
            error!("Invalid base64 encoding: {}", e);
            ApiError::BadRequest
        })?;

    // Encrypt the secret bytes with the enclave key
    let secret_key = SecretKey::from_slice(&data.enclave_key).map_err(|e| {
        error!("Failed to create secret key: {}", e);
        ApiError::InternalServerError
    })?;
    let encrypted_secret = crate::encrypt::encrypt_with_key(&secret_key, &secret_bytes).await;

    // Create the new secret
    let new_secret = NewOrgProjectSecret::new(
        project.id,
        create_request.key_name.clone(),
        encrypted_secret,
    );

    let secret = data.db.create_org_project_secret(new_secret).map_err(|e| {
        error!("Failed to create project secret: {:?}", e);
        ApiError::InternalServerError
    })?;

    let response = SecretResponse {
        key_name: secret.key_name,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
    };

    encrypt_response(&data, &session_id, &response).await
}

async fn list_secrets(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id)): Path<(Uuid, Uuid)>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<Vec<SecretResponse>>>, ApiError> {
    debug!("Listing project secrets");

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data.db.get_org_project_by_uuid(project_id).map_err(|_| {
        error!("Project not found");
        ApiError::NotFound
    })?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        error!("Project does not belong to organization");
        return Err(ApiError::NotFound);
    }

    // Verify user has any role in the org
    let _membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    // Get all secrets for the project
    let secrets = data
        .db
        .get_all_org_project_secrets_for_project(project.id)
        .map_err(|e| {
            error!("Failed to get project secrets: {:?}", e);
            ApiError::InternalServerError
        })?;

    let response: Vec<SecretResponse> = secrets
        .into_iter()
        .map(|s| SecretResponse {
            key_name: s.key_name,
            created_at: s.created_at,
            updated_at: s.updated_at,
        })
        .collect();

    encrypt_response(&data, &session_id, &response).await
}

async fn delete_secret(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id, key_name)): Path<(Uuid, Uuid, String)>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<serde_json::Value>>, ApiError> {
    debug!("Deleting project secret");

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data.db.get_org_project_by_uuid(project_id).map_err(|_| {
        error!("Project not found");
        ApiError::NotFound
    })?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        error!("Project does not belong to organization");
        return Err(ApiError::NotFound);
    }

    // Verify user has admin or owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    let role: OrgRole = membership.role.into();
    if !matches!(role, OrgRole::Owner | OrgRole::Admin) {
        return Err(ApiError::Unauthorized);
    }

    // Get the secret
    let secret = data
        .db
        .get_org_project_secret_by_key_name_and_project(&key_name, project.id)
        .map_err(|e| {
            error!("Failed to get project secret: {:?}", e);
            ApiError::InternalServerError
        })?
        .ok_or_else(|| {
            error!("Secret not found");
            ApiError::NotFound
        })?;

    // Delete the secret
    data.db.delete_org_project_secret(&secret).map_err(|e| {
        error!("Failed to delete project secret: {:?}", e);
        ApiError::InternalServerError
    })?;

    let response = serde_json::json!({
        "message": "Secret deleted successfully"
    });

    encrypt_response(&data, &session_id, &response).await
}

async fn get_project_settings(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id, category)): Path<(Uuid, Uuid, String)>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<ProjectSettingResponse>>, ApiError> {
    debug!("Getting project settings");

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data.db.get_org_project_by_uuid(project_id).map_err(|_| {
        error!("Project not found");
        ApiError::NotFound
    })?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        error!("Project does not belong to organization");
        return Err(ApiError::NotFound);
    }

    // Verify user has any role in the org
    let _membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    // Parse category
    let setting_category = match category.as_str() {
        "email" => SettingCategory::Email,
        _ => {
            error!("Invalid settings category: {}", category);
            return Err(ApiError::BadRequest);
        }
    };

    // Get settings
    let settings = data
        .db
        .get_project_settings(project.id, setting_category)?
        .ok_or_else(|| {
            error!("Settings not found");
            ApiError::NotFound
        })?;

    let response = ProjectSettingResponse {
        category: settings.category,
        settings: settings.settings,
        created_at: settings.created_at,
        updated_at: settings.updated_at,
    };

    encrypt_response(&data, &session_id, &response).await
}

async fn update_project_settings(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id, category)): Path<(Uuid, Uuid, String)>,
    Extension(update_request): Extension<UpdateProjectSettingsRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<ProjectSettingResponse>>, ApiError> {
    debug!("Updating project settings");

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data.db.get_org_project_by_uuid(project_id).map_err(|_| {
        error!("Project not found");
        ApiError::NotFound
    })?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        error!("Project does not belong to organization");
        return Err(ApiError::NotFound);
    }

    // Verify user has admin or owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    let role: OrgRole = membership.role.into();
    if !matches!(role, OrgRole::Owner | OrgRole::Admin) {
        return Err(ApiError::Unauthorized);
    }

    // Parse category
    let setting_category = match category.as_str() {
        "email" => SettingCategory::Email,
        _ => {
            error!("Invalid settings category: {}", category);
            return Err(ApiError::BadRequest);
        }
    };

    // Update settings
    let settings =
        data.db
            .update_project_settings(project.id, setting_category, update_request.settings)?;

    let response = ProjectSettingResponse {
        category: settings.category,
        settings: settings.settings,
        created_at: settings.created_at,
        updated_at: settings.updated_at,
    };

    encrypt_response(&data, &session_id, &response).await
}

async fn get_email_settings(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id)): Path<(Uuid, Uuid)>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<EmailSettings>>, ApiError> {
    debug!("Getting project email settings");

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data.db.get_org_project_by_uuid(project_id).map_err(|_| {
        error!("Project not found");
        ApiError::NotFound
    })?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        error!("Project does not belong to organization");
        return Err(ApiError::NotFound);
    }

    // Verify user has any role in the org
    let _membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    // Get email settings
    let settings = data
        .db
        .get_project_email_settings(project.id)?
        .ok_or_else(|| {
            error!("Email settings not found");
            ApiError::NotFound
        })?;

    encrypt_response(&data, &session_id, &settings).await
}

async fn update_email_settings(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id)): Path<(Uuid, Uuid)>,
    Extension(update_request): Extension<UpdateEmailSettingsRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<EmailSettings>>, ApiError> {
    debug!("Updating project email settings");

    // Validate request
    if let Err(errors) = update_request.validate() {
        error!("Validation error: {:?}", errors);
        return Err(ApiError::BadRequest);
    }

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data.db.get_org_project_by_uuid(project_id).map_err(|_| {
        error!("Project not found");
        ApiError::NotFound
    })?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        error!("Project does not belong to organization");
        return Err(ApiError::NotFound);
    }

    // Verify user has admin or owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    let role: OrgRole = membership.role.into();
    if !matches!(role, OrgRole::Owner | OrgRole::Admin) {
        return Err(ApiError::Unauthorized);
    }

    // Create email settings
    let email_settings = EmailSettings {
        provider: update_request.provider,
        send_from: update_request.send_from,
        email_verification_url: update_request.email_verification_url,
    };

    // Update settings and get the result back
    let settings = data
        .db
        .update_project_email_settings(project.id, email_settings)?;

    // Get the updated settings from the database to return
    let updated_settings = settings.get_email_settings().map_err(|e| {
        error!("Failed to parse updated email settings: {:?}", e);
        ApiError::InternalServerError
    })?;

    encrypt_response(&data, &session_id, &updated_settings).await
}

async fn get_oauth_settings(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id)): Path<(Uuid, Uuid)>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<OAuthSettings>>, ApiError> {
    debug!("Getting project OAuth settings");

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data.db.get_org_project_by_uuid(project_id).map_err(|_| {
        error!("Project not found");
        ApiError::NotFound
    })?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        error!("Project does not belong to organization");
        return Err(ApiError::NotFound);
    }

    // Verify user has any role in the org
    let _membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    // Get OAuth settings
    let settings = data
        .db
        .get_project_oauth_settings(project.id)?
        .unwrap_or_default();

    encrypt_response(&data, &session_id, &settings).await
}

async fn update_oauth_settings(
    State(data): State<Arc<AppState>>,
    Extension(platform_user): Extension<PlatformUser>,
    Path((org_id, project_id)): Path<(Uuid, Uuid)>,
    Extension(update_request): Extension<UpdateOAuthSettingsRequest>,
    Extension(session_id): Extension<Uuid>,
) -> Result<Json<EncryptedResponse<OAuthSettings>>, ApiError> {
    debug!("Updating project OAuth settings");

    // Validate request
    if let Err(errors) = update_request.validate() {
        error!("Validation error: {:?}", errors);
        return Err(ApiError::BadRequest);
    }

    // Get org and project by UUID
    let org = data
        .db
        .get_org_by_uuid(org_id)
        .map_err(|_| ApiError::NotFound)?;

    let project = data.db.get_org_project_by_uuid(project_id).map_err(|_| {
        error!("Project not found");
        ApiError::NotFound
    })?;

    // Ensure project belongs to org
    if project.org_id != org.id {
        error!("Project does not belong to organization");
        return Err(ApiError::NotFound);
    }

    // Verify user has admin or owner role
    let membership = data
        .db
        .get_org_membership_by_platform_user_and_org(platform_user.uuid, org.id)
        .map_err(|_| ApiError::Unauthorized)?;

    let role: OrgRole = membership.role.into();
    if !matches!(role, OrgRole::Owner | OrgRole::Admin) {
        return Err(ApiError::Unauthorized);
    }

    // Create OAuth settings
    let oauth_settings = OAuthSettings {
        google_oauth_enabled: update_request.google_oauth_enabled,
        github_oauth_enabled: update_request.github_oauth_enabled,
        google_oauth_settings: update_request.google_oauth_settings,
        github_oauth_settings: update_request.github_oauth_settings,
    };

    // Update settings
    let settings = data
        .db
        .update_project_oauth_settings(project.id, oauth_settings)?;

    // Get the updated settings from the database to return
    let updated_settings = settings.get_oauth_settings().map_err(|e| {
        error!("Failed to parse updated oauth settings: {:?}", e);
        ApiError::InternalServerError
    })?;

    encrypt_response(&data, &session_id, &updated_settings).await
}
