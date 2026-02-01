use resend_rs::{Client, Result};
use resend_rs::types::SendEmail;
use std::sync::Arc;

#[derive(Clone)]
pub struct EmailService {
    client: Arc<Client>,
    from_email: String,
    from_name: String,
    base_url: String,
}

impl EmailService {
    pub fn new(api_key: String, from_email: String, from_name: String, base_url: String) -> Self {
        let client = Client::new(&api_key);
        Self {
            client: Arc::new(client),
            from_email,
            from_name,
            base_url,
        }
    }

    pub async fn send_verification_email(&self, to_email: &str, verification_token: &str) -> Result<()> {
        let from = format!("{} <{}>", self.from_name, self.from_email);
        let to = [to_email];
        let subject = "Verify Your Email Address";

        let verification_url = format!("{}/api/v1/auth/verify-email/{}", self.base_url, verification_token);

        let html = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Verify Your Email</title>
            </head>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #333; text-align: center;">Verify Your Email Address</h1>
                <p style="color: #666; line-height: 1.6;">
                    Welcome! Please click the button below to verify your email address and complete your registration.
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{}" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Verify Email
                    </a>
                </div>
                <p style="color: #999; font-size: 14px;">
                    If the button doesn't work, copy and paste this link into your browser:<br>
                    <a href="{}">{}</a>
                </p>
                <p style="color: #999; font-size: 12px;">
                    This link will expire in 24 hours.
                </p>
            </body>
            </html>
            "#,
            verification_url, verification_url, verification_url
        );

        let email = SendEmail::new(from, to, subject)
            .with_html(&html);

        self.client.emails.send(email).await?;
        Ok(())
    }

    pub async fn send_password_reset_email(&self, to_email: &str, reset_token: &str) -> Result<()> {
        let from = format!("{} <{}>", self.from_name, self.from_email);
        let to = [to_email];
        let subject = "Reset Your Password";

        let reset_url = format!("{}/reset-password?token={}", self.base_url, reset_token);

        let html = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Reset Your Password</title>
            </head>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #333; text-align: center;">Reset Your Password</h1>
                <p style="color: #666; line-height: 1.6;">
                    We received a request to reset your password. Click the button below to create a new password.
                </p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{}" style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
                        Reset Password
                    </a>
                </div>
                <p style="color: #666; line-height: 1.6;">
                    If you didn't request this password reset, you can safely ignore this email.
                </p>
                <p style="color: #999; font-size: 14px;">
                    If the button doesn't work, copy and paste this link into your browser:<br>
                    <a href="{}">{}</a>
                </p>
                <p style="color: #999; font-size: 12px;">
                    This link will expire in 1 hour.
                </p>
            </body>
            </html>
            "#,
            reset_url, reset_url, reset_url
        );

        let email = SendEmail::new(from, to, subject)
            .with_html(&html);

        self.client.emails.send(email).await?;
        Ok(())
    }
}