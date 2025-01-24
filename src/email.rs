use crate::AppMode;
use chrono::{Duration, Utc};
use resend_rs::types::CreateEmailBaseOptions;
use resend_rs::{Resend, Result};
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("Unknown Email error")]
    UnknownError,
    #[error("Resend API key not found")]
    ApiKeyNotFound,
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
        <p>We're thrilled to have you join us during our private beta.</p>

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

        <p>As we're in private beta, your feedback is incredibly valuable. If you encounter any issues or have suggestions, please reach out to us at <a href="mailto:team@opensecret.cloud">team@opensecret.cloud</a>.</p>

        <p>Thank you for being an early adopter and helping us shape the future of secure, AI-powered productivity!</p>

        <p>Best regards,<br>The OpenSecret Team</p>
    </div>
</body>
</html>
"#;

pub async fn send_hello_email(
    app_mode: AppMode,
    resend_api_key: Option<String>,
    to_email: String,
) -> Result<(), EmailError> {
    tracing::debug!("Entering send_hello_email");
    if resend_api_key.is_none() {
        return Err(EmailError::ApiKeyNotFound);
    }
    let api_key = resend_api_key.expect("just checked");

    let resend = Resend::new(&api_key);

    let from = from_email(app_mode);
    let to = [to_email];
    let subject = "Welcome to Maple!";

    // Schedule the email to be sent 5 minutes from now
    let scheduled_time = Utc::now() + Duration::minutes(5);
    let scheduled_at = scheduled_time.to_rfc3339();

    let email = CreateEmailBaseOptions::new(from, to, subject)
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
    app_mode: AppMode,
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

    let from = from_email(app_mode.clone());
    let to = [to_email];
    let subject = "Verify Your Maple AI Account";

    let base_url = match app_mode {
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
            <title>Verify Your Maple AI Account</title>
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
                <h1>Welcome to Maple AI!</h1>
                <p>Thank you for registering. To complete your account setup, please verify your email address by clicking the button below:</p>
                <p>
                    <a href="{}" class="button">Verify Your Email</a>
                </p>
                <p>If the button doesn't work, you can copy and paste the following link into your browser:</p>
                <p>{}</p>
                <p>Alternatively, you can use the following verification code:</p>
                <p class="code">{}</p>
                <p>This verification link and code will expire in 24 hours.</p>
                <p>If you didn't create an account with Maple AI, please ignore this email.</p>
                <p>Best regards,<br>The OpenSecret Team</p>
            </div>
        </body>
        </html>
        "#,
        verification_url, verification_url, verification_code
    );

    let email = CreateEmailBaseOptions::new(from, to, subject).with_html(&html_content);

    let _email = resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Failed to send email: {}", e);
        EmailError::UnknownError
    });

    tracing::debug!("Exiting send_verification_email");
    Ok(())
}

pub async fn send_password_reset_email(
    app_mode: AppMode,
    resend_api_key: Option<String>,
    to_email: String,
    alphanumeric_code: String,
) -> Result<(), EmailError> {
    tracing::debug!("Entering send_password_reset_email");
    if resend_api_key.is_none() {
        return Err(EmailError::ApiKeyNotFound);
    }
    let api_key = resend_api_key.expect("just checked");

    let resend = Resend::new(&api_key);

    let from = from_email(app_mode);
    let to = [to_email];
    let subject = "Reset Your Maple AI Password";

    let html_content = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Your Maple AI Password</title>
            <style>
                body {{ font-family: ui-sans-serif,system-ui,sans-serif; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                h1, h2, h3 {{ font-weight: 300; }}
                .code {{ background-color: rgba(1,1,1,0.05); padding: 10px; border-radius: 5px; font-family: monospace; font-size: 16px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Reset Your Maple AI Password</h1>
                <p>We received a request to reset your Maple AI account password. If you didn't make this request, you can ignore this email.</p>
                <p>To reset your password, use the following code:</p>
                <p class="code">{}</p>
                <p>This code will expire in 24 hours.</p>
                <p>If you have any issues, please contact our support team.</p>
                <p>Best regards,<br>The OpenSecret Team</p>
            </div>
        </body>
        </html>
        "#,
        alphanumeric_code
    );

    let email = CreateEmailBaseOptions::new(from, to, subject).with_html(&html_content);

    let _email = resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Failed to send email: {}", e);
        EmailError::UnknownError
    });

    tracing::debug!("Exiting send_password_reset_email");
    Ok(())
}

pub async fn send_password_reset_confirmation_email(
    app_mode: AppMode,
    resend_api_key: Option<String>,
    to_email: String,
) -> Result<(), EmailError> {
    tracing::debug!("Entering send_password_reset_confirmation_email");
    if resend_api_key.is_none() {
        return Err(EmailError::ApiKeyNotFound);
    }
    let api_key = resend_api_key.expect("just checked");

    let resend = Resend::new(&api_key);

    let from = from_email(app_mode);
    let to = [to_email];
    let subject = "Your Maple AI Password Has Been Reset";

    let html_content = r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset Confirmation</title>
            <style>
                body { font-family: ui-sans-serif,system-ui,sans-serif; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                h1, h2, h3 { font-weight: 300; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Password Reset Confirmation</h1>
                <p>Your Maple AI account password has been successfully reset.</p>
                <p>If you did not initiate this password reset, please contact us immediately at <a href="mailto:support@trymaple.ai">support@trymaple.ai</a>.</p>
                <p>For security reasons, we recommend that you:</p>
                <ul>
                    <li>Change your password again if you suspect any unauthorized access.</li>
                    <li>Review your account activity for any suspicious actions.</li>
                </ul>
                <p>If you have any questions or concerns, please don't hesitate to reach out to our support team.</p>
                <p>Best regards,<br>The Maple AI Team</p>
            </div>
        </body>
        </html>
    "#;

    let email = CreateEmailBaseOptions::new(from, to, subject).with_html(html_content);

    let _email = resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Failed to send email: {}", e);
        EmailError::UnknownError
    });

    tracing::debug!("Exiting send_password_reset_confirmation_email");
    Ok(())
}

fn from_email(app_mode: AppMode) -> String {
    match app_mode {
        AppMode::Local => "local@email.trymaple.ai".to_string(),
        AppMode::Dev => "dev@email.trymaple.ai".to_string(),
        AppMode::Preview => "preview@email.trymaple.ai".to_string(),
        AppMode::Prod => "hello@email.trymaple.ai".to_string(),
        AppMode::Custom(_) => "preview@email.trymaple.ai".to_string(),
    }
}
