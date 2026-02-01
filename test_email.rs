use dotenvy::dotenv;
use resend_rs::{Client, Result};
use resend_rs::types::SendEmail;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let api_key = std::env::var("RESEND_API_KEY")
        .expect("RESEND_API_KEY must be set");

    let client = Client::new(&api_key);

    let from = "Universal Auth Service <noreply@resend.dev>";
    let to = ["delivered@resend.dev"];
    let subject = "Test Email from Universal Auth Service";

    let html = r#"
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Test Email</title>
    </head>
    <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h1 style="color: #333; text-align: center;">Test Email</h1>
        <p style="color: #666; line-height: 1.6;">
            This is a test email from the Universal Auth Service. If you received this, the email integration is working correctly!
        </p>
        <div style="text-align: center; margin: 30px 0;">
            <div style="background-color: #007bff; color: white; padding: 12px 24px; border-radius: 5px; display: inline-block;">
                ✅ Email Service Working
            </div>
        </div>
    </body>
    </html>
    "#;

    let email = SendEmail::new(from, to, subject)
        .with_html(html);

    let email_id = client.emails.send(email).await?;
    println!("✅ Test email sent successfully! Email ID: {}", email_id);

    Ok(())
}