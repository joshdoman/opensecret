use crate::AppMode;
use crate::DBError;
use crate::PROJECT_RESEND_API_KEY;
use chrono::{Duration, Utc};
use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::{Resend, Result};
use tracing::error;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("Unknown Email error")]
    UnknownError,
    #[error("Resend API key not found")]
    ApiKeyNotFound,
    #[error("Project email settings not found")]
    ProjectSettingsNotFound,
    #[error("Project email settings incomplete")]
    IncompleteSettings,
    #[error("Database error: {0}")]
    DatabaseError(#[from] DBError),
}

const WELCOME_EMAIL_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to Maple AI</title>
    <style>
        body { font-family: ui-sans-serif,system-ui,sans-serif; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        h1, h2, h3 { font-weight: 300; }
        .security-features { background-color: rgba(0,0,0,0.05); padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to <a href="https://trymaple.ai">Maple AI</a>!</h1>
        <p>We're thrilled to have you join us.</p>

        <p><em>Just as Maple trees thrive through their discreet underground communication network of fungal hyphae, Maple AI empowers you to flourish in the digital world while maintaining your privacy.</em></p>

        <h2>Your Secure, AI-Powered Second Brain</h2>
        <p>Maple AI is designed with privacy and security at its core, helping you:</p>
        <ul>
            <li>Organize your thoughts</li>
            <li>Enhance your creativity</li>
            <li>Boost your productivity</li>
        </ul>
        <p>With Maple AI, you can chat with your notes, create new ideas, and connect concepts effortlessly, all while maintaining complete control over your data.</p>
        
        <div class="security-features">
            <h3>Privacy: Our Core Value</h3>
            <ul>
                <li><strong>Confidential Compute:</strong> Secure enclaves ensure we can't see your requests.</li>
                <li><strong>End-to-End Encryption:</strong> Your chat history is synced with a private key we can't access.</li>
                <li><strong>Encrypted GPU:</strong> Enjoy a private 1:1 conversation with your AI companion.</li>
            </ul>
        </div>

        <p>At OpenSecret, we believe privacy is essential for trusted conversations – not just with people, but also with AI. By prioritizing your privacy, we're creating a more secure world that puts individual needs and values at its core.</p>

        <p>We hope you enjoy using Maple AI, knowing that your sensitive discussions and data are protected at every step. Your privacy is not just a feature – it's our mission.</p>

        <p>Your feedback is incredibly valuable. If you encounter any issues or have suggestions, please reach out to us at <a href="mailto:support@opensecret.cloud">support@opensecret.cloud</a>.</p>

        <p>Thank you for being an early adopter and helping us shape the future of secure, AI-powered productivity!</p>

        <p>Best regards,<br>The OpenSecret Team</p>
    </div>
</body>
</html>
"#;

async fn get_project_email_settings(
    app_state: &crate::AppState,
    project_id: i32,
) -> Result<(String, String), EmailError> {
    // Get project email settings
    let email_settings = app_state
        .db
        .get_project_email_settings(project_id)?
        .ok_or(EmailError::ProjectSettingsNotFound)?;

    // Verify provider is resend
    if email_settings.provider != "resend" {
        error!("Unsupported email provider: {}", email_settings.provider);
        return Err(EmailError::IncompleteSettings);
    }

    // Verify send_from is set
    if email_settings.send_from.is_empty() {
        error!("Project send_from email not configured");
        return Err(EmailError::IncompleteSettings);
    }

    // Get project's Resend API key
    let secret = app_state
        .db
        .get_org_project_secret_by_key_name_and_project(PROJECT_RESEND_API_KEY, project_id)?
        .ok_or(EmailError::ApiKeyNotFound)?;

    // Decrypt the API key
    let secret_key = secp256k1::SecretKey::from_slice(&app_state.enclave_key)
        .map_err(|_| EmailError::UnknownError)?;
    let api_key = String::from_utf8(
        crate::encrypt::decrypt_with_key(&secret_key, &secret.secret_enc)
            .map_err(|_| EmailError::UnknownError)?,
    )
    .map_err(|_| EmailError::UnknownError)?;

    Ok((api_key, email_settings.send_from))
}

// TODO remove the send email and do it outside of the enclave
pub async fn send_hello_email(
    app_state: &crate::AppState,
    project_id: i32,
    to_email: String,
) -> Result<(), EmailError> {
    tracing::debug!("Entering send_hello_email");

    // Get project name
    let project = app_state
        .db
        .get_org_project_by_id(project_id)
        .map_err(|e| {
            error!("Failed to get project: {}", e);
            EmailError::UnknownError
        })?;

    // Only send welcome email for Maple project for now
    if project.name != "Maple" {
        tracing::debug!("Skipping welcome email for non-Maple project");
        return Ok(());
    }

    tracing::debug!("Sending maple hello email");

    let (api_key, from_email) = get_project_email_settings(app_state, project_id).await?;
    let resend = Resend::new(&api_key);

    let to = [to_email];
    let subject = format!("Welcome to {}!", project.name);

    // Schedule the email to be sent 5 minutes from now
    let scheduled_time = Utc::now() + Duration::minutes(5);
    let scheduled_at = scheduled_time.to_rfc3339();

    let email = CreateEmailBaseOptions::new(from_email, to, subject)
        .with_html(WELCOME_EMAIL_HTML)
        .with_scheduled_at(&scheduled_at);

    let _email = resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Failed to send email: {}", e);
        EmailError::UnknownError
    });

    tracing::debug!("Exiting send_hello_email");
    Ok(())
}

pub async fn send_verification_email(
    app_state: &crate::AppState,
    project_id: i32,
    to_email: String,
    verification_code: uuid::Uuid,
) -> Result<(), EmailError> {
    tracing::debug!("Entering send_verification_email");

    let (api_key, from_email) = get_project_email_settings(app_state, project_id).await?;
    let resend = Resend::new(&api_key);

    // Get project name and email settings
    let project = app_state
        .db
        .get_org_project_by_id(project_id)
        .map_err(|e| {
            error!("Failed to get project: {}", e);
            EmailError::UnknownError
        })?;

    let email_settings = app_state
        .db
        .get_project_email_settings(project_id)?
        .ok_or(EmailError::ProjectSettingsNotFound)?;

    let to = [to_email];
    let subject = format!("Verify Your {} Account", project.name);

    // Ensure base URL has exactly one trailing slash
    let base_url = email_settings.email_verification_url.trim_end_matches('/');
    let verification_url = format!("{}/{}", base_url, verification_code);

    let html_content = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify Your {} Account</title>
            <style>
                body {{ font-family: ui-sans-serif,system-ui,sans-serif; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                h1, h2, h3 {{ font-weight: 300; }}
                .button {{ display: inline-block; padding: 10px 20px; background-color: black; color: #ffffff; text-decoration: none; border-radius: 5px; }}
                .code {{ background-color: rgba(1,1,1,0.05); padding: 10px; border-radius: 5px; font-family: monospace; font-size: 16px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to {}!</h1>
                <p>Thank you for registering. To complete your account setup, please verify your email address by clicking the button below:</p>
                <p>
                    <a href="{}" class="button">Verify Your Email</a>
                </p>
                <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
                <p>{}</p>
                <p>Alternatively, you can use the following verification code:</p>
                <p class="code">{}</p>
                <p>This verification link and code will expire in 24 hours.</p>
                <p>If you didn't create an account with {}, please ignore this email.</p>
                <p>Best regards,<br>The OpenSecret Team</p>
            </div>
        </body>
        </html>
        "#,
        project.name,
        project.name,
        verification_url,
        verification_url,
        verification_code,
        project.name
    );

    let email = CreateEmailBaseOptions::new(from_email, to, subject).with_html(&html_content);

    let _email = resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Failed to send email: {}", e);
        EmailError::UnknownError
    });

    tracing::debug!("Exiting send_verification_email");
    Ok(())
}

pub async fn send_password_reset_email(
    app_state: &crate::AppState,
    project_id: i32,
    to_email: String,
    alphanumeric_code: String,
) -> Result<(), EmailError> {
    tracing::debug!("Entering send_password_reset_email");

    let (api_key, from_email) = get_project_email_settings(app_state, project_id).await?;
    let resend = Resend::new(&api_key);

    // Get project name
    let project = app_state
        .db
        .get_org_project_by_id(project_id)
        .map_err(|e| {
            error!("Failed to get project: {}", e);
            EmailError::UnknownError
        })?;

    let to = [to_email];
    let subject = format!("Reset Your {} Password", project.name);

    let html_content = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Your {} Password</title>
            <style>
                body {{ font-family: ui-sans-serif,system-ui,sans-serif; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                h1, h2, h3 {{ font-weight: 300; }}
                .code {{ background-color: rgba(1,1,1,0.05); padding: 10px; border-radius: 5px; font-family: monospace; font-size: 16px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Reset Your {} Password</h1>
                <p>We received a request to reset your {} account password. If you didn't make this request, you can ignore this email.</p>
                <p>To reset your password, use the following code:</p>
                <p class="code">{}</p>
                <p>This code will expire in 24 hours.</p>
                <p>If you have any issues, please contact our support team.</p>
                <p>Best regards,<br>The OpenSecret Team</p>
            </div>
        </body>
        </html>
        "#,
        project.name, project.name, project.name, alphanumeric_code
    );

    let email = CreateEmailBaseOptions::new(from_email, to, subject).with_html(&html_content);

    let _email = resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Failed to send email: {}", e);
        EmailError::UnknownError
    });

    tracing::debug!("Exiting send_password_reset_email");
    Ok(())
}

pub async fn send_password_reset_confirmation_email(
    app_state: &crate::AppState,
    project_id: i32,
    to_email: String,
) -> Result<(), EmailError> {
    tracing::debug!("Entering send_password_reset_confirmation_email");

    let (api_key, from_email) = get_project_email_settings(app_state, project_id).await?;
    let resend = Resend::new(&api_key);

    // Get project name
    let project = app_state
        .db
        .get_org_project_by_id(project_id)
        .map_err(|e| {
            error!("Failed to get project: {}", e);
            EmailError::UnknownError
        })?;

    let to = [to_email];
    let subject = format!("Your {} Password Has Been Reset", project.name);

    let html_content = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset Confirmation</title>
            <style>
                body {{ font-family: ui-sans-serif,system-ui,sans-serif; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                h1, h2, h3 {{ font-weight: 300; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Password Reset Confirmation</h1>
                <p>Your {} account password has been successfully reset.</p>
                <p>If you did not initiate this password reset, please contact us immediately at <a href="mailto:support@opensecret.cloud">support@opensecret.cloud</a>.</p>
                <p>For security reasons, we recommend that you:</p>
                <ul>
                    <li>Change your password again if you suspect any unauthorized access.</li>
                    <li>Review your account activity for any suspicious actions.</li>
                </ul>
                <p>If you have any questions or concerns, please don't hesitate to reach out to our support team.</p>
                <p>Best regards,<br>The OpenSecret Team</p>
            </div>
        </body>
        </html>
        "#,
        project.name
    );

    let email = CreateEmailBaseOptions::new(from_email, to, subject).with_html(&html_content);

    let _email = resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Failed to send email: {}", e);
        EmailError::UnknownError
    });

    tracing::debug!("Exiting send_password_reset_confirmation_email");
    Ok(())
}

pub async fn send_platform_verification_email(
    app_state: &crate::AppState,
    resend_api_key: Option<String>,
    to_email: String,
    verification_code: uuid::Uuid,
) -> Result<(), EmailError> {
    tracing::debug!("Entering send_verification_email");

    if resend_api_key.is_none() {
        return Err(EmailError::ApiKeyNotFound);
    }
    let api_key = resend_api_key.expect("just checked");

    let resend = Resend::new(&api_key);

    let to = [to_email];
    let from_email = from_opensecret_email(app_state.app_mode.clone());
    let subject = "Verify Your OpenSecret Account";

    let base_url = match app_state.app_mode {
        AppMode::Local => "http://localhost:5173",
        AppMode::Dev => "https://dev.secretgpt.ai",
        AppMode::Preview => "https://opensecret.cloud",
        AppMode::Prod => "https://trymaple.ai",
        AppMode::Custom(_) => "https://preview.opensecret.cloud",
    };

    let verification_url = format!("{}/verify/{}", base_url, verification_code);

    let html_content = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify Your OpenSecret Account</title>
            <style>
                body {{ font-family: ui-sans-serif,system-ui,sans-serif; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                h1, h2, h3 {{ font-weight: 300; }}
                .button {{ display: inline-block; padding: 10px 20px; background-color: black; color: #ffffff; text-decoration: none; border-radius: 5px; }}
                .code {{ background-color: rgba(1,1,1,0.05); padding: 10px; border-radius: 5px; font-family: monospace; font-size: 16px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to OpenSecret!</h1>
                <p>Thank you for registering. To complete your account setup, please verify your email address by clicking the button below:</p>
                <p>
                    <a href="{}" class="button">Verify Your Email</a>
                </p>
                <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
                <p>{}</p>
                <p>Alternatively, you can use the following verification code:</p>
                <p class="code">{}</p>
                <p>This verification link and code will expire in 24 hours.</p>
                <p>If you didn't create an account with OpenSecret, please ignore this email.</p>
                <p>Best regards,<br>The OpenSecret Team</p>
            </div>
        </body>
        </html>
        "#,
        verification_url, verification_url, verification_code
    );

    let email = CreateEmailBaseOptions::new(from_email, to, subject).with_html(&html_content);

    let _email = resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Failed to send email: {}", e);
        EmailError::UnknownError
    });

    tracing::debug!("Exiting send_verification_email");
    Ok(())
}

pub async fn send_platform_invite_email(
    app_mode: AppMode,
    resend_api_key: Option<String>,
    to_email: String,
    organization_name: String,
    invite_code: Uuid,
) -> Result<(), EmailError> {
    tracing::debug!("Entering send_invite_email");
    if resend_api_key.is_none() {
        return Err(EmailError::ApiKeyNotFound);
    }
    let api_key = resend_api_key.expect("just checked");

    let resend = Resend::new(&api_key);

    let from = from_opensecret_email(app_mode.clone());
    let to = [to_email];
    let subject = "You've Been Invited to Join an Organization on OpenSecret";

    let base_url = match app_mode {
        AppMode::Local => "http://localhost:5173",
        AppMode::Dev => "https://dev.secretgpt.ai",
        AppMode::Preview => "https://opensecret.cloud",
        AppMode::Prod => "https://trymaple.ai",
        AppMode::Custom(_) => "https://preview.opensecret.cloud",
    };

    let invite_url = format!("{}/join/{}", base_url, invite_code);

    let html_content = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Organization Invitation - OpenSecret</title>
            <style>
                body {{ font-family: ui-sans-serif,system-ui,sans-serif; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                h1, h2, h3 {{ font-weight: 300; }}
                .button {{ display: inline-block; padding: 10px 20px; background-color: black; color: #ffffff; text-decoration: none; border-radius: 5px; }}
                .code {{ background-color: rgba(1,1,1,0.05); padding: 10px; border-radius: 5px; font-family: monospace; font-size: 16px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>You've Been Invited!</h1>
                <p>You've been invited to join the {} organization on OpenSecret. To accept this invitation, please click the button below:</p>
                <p>
                    <a href="{}" class="button">Accept Invitation</a>
                </p>
                <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
                <p>{}</p>
                <p>Alternatively, you can use the following invitation code:</p>
                <p class="code">{}</p>
                <p>This invitation link and code will expire in 24 hours.</p>
                <p>If you weren't expecting this invitation, you can safely ignore this email.</p>
                <p>Best regards,<br>The OpenSecret Team</p>
            </div>
        </body>
        </html>
        "#,
        organization_name, invite_url, invite_url, invite_code
    );

    let email = CreateEmailBaseOptions::new(from, to, subject).with_html(&html_content);

    let _email = resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Failed to send email: {}", e);
        EmailError::UnknownError
    });

    tracing::debug!("Exiting send_invite_email");
    Ok(())
}

fn from_opensecret_email(app_mode: AppMode) -> String {
    // TODO change these to opensecret domains and only use for platform
    match app_mode {
        AppMode::Local => "local@email.trymaple.ai".to_string(),
        AppMode::Dev => "dev@email.trymaple.ai".to_string(),
        AppMode::Preview => "preview@email.trymaple.ai".to_string(),
        AppMode::Prod => "hello@email.trymaple.ai".to_string(),
        AppMode::Custom(_) => "preview@email.trymaple.ai".to_string(),
    }
}
