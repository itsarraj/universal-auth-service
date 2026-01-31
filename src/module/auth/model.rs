use uuid::Uuid;
use serde::{Deserialize, Serialize};
use chrono::NaiveDateTime;
use sqlx::Row;

// ===== REQUEST/RESPONSE MODELS =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: String, // "user", "admin", etc.
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub email: String,
    pub email_verification_token: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserProfile,
    pub expires_in: i64, // seconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String, // new refresh token
    pub expires_in: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub role: String,
    pub email_verified: bool,
    pub created_at: NaiveDateTime,
}

// ===== JWT TOKEN MODELS =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String, // user_id
    pub email: String,
    pub role: String,
    pub exp: i64, // expiration timestamp
    pub iat: i64, // issued at timestamp
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
}

// ===== DATABASE MODELS =====

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub role: String,
    pub email_verified: bool,
    pub email_verification_token: Option<String>,
    pub password_reset_token: Option<String>,
    pub password_reset_expires_at: Option<NaiveDateTime>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl User {
    pub fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
            password_hash: row.try_get("password_hash")?,
            name: row.try_get("name")?,
            role: row.try_get("role")?,
            email_verified: row.try_get("email_verified")?,
            email_verification_token: row.try_get("email_verification_token")?,
            password_reset_token: row.try_get("password_reset_token")?,
            password_reset_expires_at: row.try_get("password_reset_expires_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    // DB schema uses TIMESTAMP (no timezone), so we store/load as NaiveDateTime
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

impl RefreshToken {
    pub fn from_row(row: &sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            token_hash: row.try_get("token_hash")?,
            expires_at: row.try_get("expires_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct TokenBlacklist {
    pub id: Uuid,
    pub token_hash: String,
    // DB schema uses TIMESTAMP (no timezone)
    pub expires_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

// ===== CACHE MODELS =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedUser {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub role: String,
    pub email_verified: bool,
    pub created_at: NaiveDateTime,
}

// ===== ERROR MODELS =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token blacklisted")]
    TokenBlacklisted,

    #[error("Too many login attempts")]
    TooManyLoginAttempts,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Invalid verification token")]
    InvalidVerificationToken,

    #[error("Password hashing error")]
    PasswordHashingError,

    #[error("Token creation error")]
    TokenCreationError,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Cache error: {0}")]
    CacheError(String),
}
