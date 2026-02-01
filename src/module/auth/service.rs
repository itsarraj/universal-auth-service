use std::sync::Arc;
use uuid::Uuid;
use chrono::{Utc, Duration};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use rand::Rng;
use sha2::Digest;
use crate::module::auth::{
    model::*,
    repository::*,
    cache::*,
};
use crate::module::email::service::EmailService;

pub struct AuthService {
    user_repo: Arc<UserRepository>,
    refresh_token_repo: Arc<RefreshTokenRepository>,
    blacklist_repo: Arc<TokenBlacklistRepository>,
    cache: Arc<AuthCache>,
    email_service: Arc<EmailService>,
    jwt_secret: String,
    access_token_expiration_hours: i64,
    refresh_token_expiration_days: i64,
}

impl AuthService {
    pub fn new(
        user_repo: UserRepository,
        refresh_token_repo: RefreshTokenRepository,
        blacklist_repo: TokenBlacklistRepository,
        cache: AuthCache,
        email_service: EmailService,
        jwt_secret: String,
        access_token_expiration_hours: i64,
        refresh_token_expiration_days: i64,
    ) -> Self {
        Self {
            user_repo: Arc::new(user_repo),
            refresh_token_repo: Arc::new(refresh_token_repo),
            blacklist_repo: Arc::new(blacklist_repo),
            cache: Arc::new(cache),
            email_service: Arc::new(email_service),
            jwt_secret,
            access_token_expiration_hours,
            refresh_token_expiration_days,
        }
    }

    // ===== REGISTRATION =====

    pub async fn register(&self, request: RegisterRequest) -> Result<RegisterResponse, AuthError> {
        // Check if user already exists
        if self.user_repo.find_by_email(&request.email).await?.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }

        // Validate password strength (basic check)
        if request.password.len() < 8 {
            return Err(AuthError::InvalidCredentials); // Could create a specific error type
        }

        // Hash password
        let password_hash = hash(request.password, DEFAULT_COST)
            .map_err(|_| AuthError::PasswordHashingError)?;

        // Generate email verification token
        let verification_token = self.generate_secure_token();

        let user = User {
            id: Uuid::new_v4(),
            email: request.email.clone(),
            password_hash,
            name: request.name,
            role: request.role,
            email_verified: false,
            email_verification_token: Some(verification_token.clone()),
            password_reset_token: None,
            password_reset_expires_at: None,
            created_at: Utc::now().naive_utc(),
            updated_at: Utc::now().naive_utc(),
        };

        self.user_repo.create_user(&user).await?;

        // Send verification email
        if let Err(e) = self.email_service.send_verification_email(&user.email, &verification_token).await {
            eprintln!("Failed to send verification email: {:?}", e);
            // Don't fail registration if email fails, but log it
        }

        Ok(RegisterResponse {
            user_id: user.id,
            email: user.email,
            email_verification_token: verification_token,
            message: "User registered successfully. Please check your email to verify your account.".to_string(),
        })
    }

    // ===== EMAIL VERIFICATION =====

    pub async fn verify_email(&self, token: &str) -> Result<(), AuthError> {
        let user = self.user_repo.find_by_verification_token(token).await?
            .ok_or(AuthError::InvalidVerificationToken)?;

        self.user_repo.update_email_verified(user.id, true).await?;

        // Invalidate cache
        self.cache.invalidate_user(user.id).await.ok(); // Don't fail if cache operation fails

        Ok(())
    }

    // ===== LOGIN =====

    pub async fn login(&self, request: LoginRequest) -> Result<LoginResponse, AuthError> {
        // Rate limiting check
        let attempts = self.cache.get_login_attempts(&request.email).await?;
        if attempts >= 5 {
            return Err(AuthError::TooManyLoginAttempts);
        }

        // Find user
        let user = self.user_repo.find_by_email(&request.email).await?
            .ok_or_else(|| {
                // Increment attempts even for non-existent users (security)
                let _ = self.cache.increment_login_attempts(&request.email);
                AuthError::InvalidCredentials
            })?;

        // Check if email is verified
        if !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        // Verify password
        if !verify(&request.password, &user.password_hash)
            .map_err(|_| AuthError::InvalidCredentials)? {
            self.cache.increment_login_attempts(&request.email).await?;
            return Err(AuthError::InvalidCredentials);
        }

        // Reset login attempts on successful login
        self.cache.reset_login_attempts(&request.email).await.ok();

        // Create JWT tokens
        let access_token = self.create_access_token(&user)?;
        let refresh_token = self.create_refresh_token(&user)?;

        // Store refresh token securely (deterministic fingerprint for lookup)
        //
        // NOTE: bcrypt is salted; hashing the presented token during refresh will never match.
        // We use a keyed SHA-256 fingerprint (jwt_secret + token) so we can lookup reliably
        // without storing the raw refresh token.
        let refresh_token_hash = self.token_fingerprint(&refresh_token);

        let refresh_token_entity = RefreshToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: refresh_token_hash,
            expires_at: (Utc::now() + Duration::days(self.refresh_token_expiration_days)).naive_utc(),
            created_at: Utc::now().naive_utc(),
        };

        self.refresh_token_repo.create(&refresh_token_entity).await?;

        // Create user profile first
        let user_profile = UserProfile {
            id: user.id,
            email: user.email.clone(),
            name: user.name.clone(),
            role: user.role.clone(),
            email_verified: user.email_verified,
            created_at: user.created_at,
        };

        // Cache user data for performance
        let cached_user = CachedUser {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            email_verified: user.email_verified,
            created_at: user.created_at,
        };
        self.cache.set_user(&cached_user).await.ok(); // Don't fail login if cache fails

        Ok(LoginResponse {
            access_token,
            refresh_token,
            user: user_profile,
            expires_in: self.access_token_expiration_hours * 3600,
        })
    }

    // ===== TOKEN REFRESH =====

    pub async fn refresh_token(&self, request: RefreshTokenRequest) -> Result<RefreshTokenResponse, AuthError> {
        // Fingerprint the incoming token for lookup (must match what we stored on login)
        let token_hash = self.token_fingerprint(&request.refresh_token);

        // Find and validate refresh token
        let stored_token = self.refresh_token_repo.find_by_hash(&token_hash).await?
            .ok_or(AuthError::InvalidToken)?;

        // Get user
        let user = self.user_repo.find_by_id(stored_token.user_id).await?
            .ok_or(AuthError::UserNotFound)?;

        // Delete old refresh token (one-time use)
        self.refresh_token_repo.delete_by_hash(&token_hash).await?;

        // Create new tokens
        let new_access_token = self.create_access_token(&user)?;
        let new_refresh_token = self.create_refresh_token(&user)?;

        // Store new refresh token
        let new_refresh_token_hash = self.token_fingerprint(&new_refresh_token);

        let new_refresh_token_entity = RefreshToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: new_refresh_token_hash,
            expires_at: (Utc::now() + Duration::days(self.refresh_token_expiration_days)).naive_utc(),
            created_at: Utc::now().naive_utc(),
        };

        self.refresh_token_repo.create(&new_refresh_token_entity).await?;

        Ok(RefreshTokenResponse {
            access_token: new_access_token,
            refresh_token: new_refresh_token,
            expires_in: self.access_token_expiration_hours * 3600,
        })
    }

    // ===== LOGOUT =====

    pub async fn logout(&self, request: LogoutRequest, user_id: Uuid) -> Result<(), AuthError> {
        // Fingerprint the refresh token for lookup
        let refresh_token_hash = self.token_fingerprint(&request.refresh_token);

        // Add refresh token to blacklist with expiration (defense-in-depth)
        let expires_at = Utc::now() + Duration::days(self.refresh_token_expiration_days);
        self.blacklist_repo
            .add_to_blacklist(&refresh_token_hash, expires_at.naive_utc())
            .await?;
        self.cache
            .add_to_blacklist(&refresh_token_hash, expires_at.timestamp())
            .await
            .ok();

        // Delete refresh token from database
        self.refresh_token_repo.delete_by_hash(&refresh_token_hash).await?;

        // Clear user cache
        self.cache.invalidate_user(user_id).await.ok();

        Ok(())
    }

    // ===== PASSWORD RESET =====

    pub async fn request_password_reset(&self, request: RequestPasswordResetRequest) -> Result<(), AuthError> {
        // Find user by email
        let user = match self.user_repo.find_by_email(&request.email).await? {
            Some(user) => user,
            None => return Ok(()), // Don't reveal if email exists for security
        };

        // Generate reset token
        let reset_token = self.generate_secure_token();
        let expires_at = Utc::now() + Duration::hours(1); // 1 hour expiry

        self.user_repo.update_password_reset_token(user.id, &reset_token, expires_at).await?;

        // Send password reset email
        if let Err(e) = self.email_service.send_password_reset_email(&user.email, &reset_token).await {
            eprintln!("Failed to send password reset email: {:?}", e);
            // Don't fail the request if email fails, but log it
        }

        Ok(())
    }

    pub async fn reset_password(&self, request: ResetPasswordRequest) -> Result<(), AuthError> {
        if request.new_password.len() < 8 {
            return Err(AuthError::InvalidCredentials);
        }

        let user = self.user_repo.find_by_password_reset_token(&request.token).await?
            .ok_or(AuthError::InvalidToken)?;

        // Hash new password
        let password_hash = hash(request.new_password, DEFAULT_COST)
            .map_err(|_| AuthError::PasswordHashingError)?;

        self.user_repo.update_password(user.id, &password_hash).await?;

        // Invalidate cache
        self.cache.invalidate_user(user.id).await.ok();

        Ok(())
    }

    // ===== PROFILE MANAGEMENT =====

    pub async fn get_profile(&self, user_id: Uuid) -> Result<UserProfile, AuthError> {
        // Try cache first
        if let Some(cached_user) = self.cache.get_user(user_id).await.ok().flatten() {
            return Ok(UserProfile {
                id: cached_user.id,
                email: cached_user.email,
                name: cached_user.name,
                role: cached_user.role,
                email_verified: cached_user.email_verified,
                created_at: cached_user.created_at,
            });
        }

        // Fallback to database
        let user = self.user_repo.find_by_id(user_id).await?
            .ok_or(AuthError::UserNotFound)?;

        // Cache for future requests
        let cached_user = CachedUser {
            id: user.id,
            email: user.email.clone(),
            name: user.name.clone(),
            role: user.role.clone(),
            email_verified: user.email_verified,
            created_at: user.created_at,
        };
        self.cache.set_user(&cached_user).await.ok();

        let profile = UserProfile {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            email_verified: user.email_verified,
            created_at: user.created_at,
        };

        Ok(profile)
    }

    pub async fn update_profile(&self, user_id: Uuid, request: UpdateProfileRequest) -> Result<(), AuthError> {
        self.user_repo.update_profile(user_id, request.name.as_deref(), request.email.as_deref()).await?;

        // Invalidate cache
        self.cache.invalidate_user(user_id).await.ok();

        Ok(())
    }

    pub async fn change_password(&self, user_id: Uuid, request: ChangePasswordRequest) -> Result<(), AuthError> {
        if request.new_password.len() < 8 {
            return Err(AuthError::InvalidCredentials);
        }

        let user = self.user_repo.find_by_id(user_id).await?
            .ok_or(AuthError::UserNotFound)?;

        // Verify current password
        if !verify(&request.current_password, &user.password_hash)
            .map_err(|_| AuthError::InvalidCredentials)? {
            return Err(AuthError::InvalidCredentials);
        }

        // Hash new password
        let password_hash = hash(request.new_password, DEFAULT_COST)
            .map_err(|_| AuthError::PasswordHashingError)?;

        self.user_repo.update_password(user.id, &password_hash).await?;

        // Invalidate cache
        self.cache.invalidate_user(user.id).await.ok();

        Ok(())
    }

    // ===== TOKEN UTILITIES =====

    pub async fn validate_token(&self, token: &str) -> Result<TokenClaims, AuthError> {
        // Check if token is blacklisted
        let token_hash = self.token_fingerprint(token);

        if self.blacklist_repo.is_blacklisted(&token_hash).await? ||
           self.cache.is_blacklisted(&token_hash).await? {
            return Err(AuthError::TokenBlacklisted);
        }

        // Decode and validate JWT
        let decoding_key = DecodingKey::from_secret(self.jwt_secret.as_ref());
        let validation = Validation::new(Algorithm::HS256);

        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }

    // ===== PRIVATE UTILITIES =====

    fn create_access_token(&self, user: &User) -> Result<String, AuthError> {
        let expiration = Utc::now() + Duration::hours(self.access_token_expiration_hours);

        let claims = TokenClaims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            role: user.role.clone(),
            exp: expiration.timestamp(),
            iat: Utc::now().timestamp(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        ).map_err(|_| AuthError::TokenCreationError)
    }

    fn create_refresh_token(&self, _user: &User) -> Result<String, AuthError> {
        // Generate a random refresh token (not JWT)
        Ok(self.generate_secure_token())
    }

    fn generate_secure_token(&self) -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    fn token_fingerprint(&self, token: &str) -> String {
        // Keyed hash (not raw sha256(token)) to make offline guessing harder if DB leaks.
        // jwt_secret is already required for issuing/verifying JWTs, so it works as the key.
        let mut hasher = sha2::Sha256::new();
        hasher.update(self.jwt_secret.as_bytes());
        hasher.update(b":");
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }
}