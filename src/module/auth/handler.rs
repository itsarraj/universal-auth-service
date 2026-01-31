use actix_web::{web, HttpResponse, Responder, HttpRequest};
use crate::{DbPool, RedisPool};
use crate::module::auth::{
    model::*,
    service::AuthService,
    repository::*,
    cache::AuthCache,
};

// ===== SHARED SERVICE INITIALIZATION =====

fn create_auth_service(
    pool: &web::Data<DbPool>,
    redis: &web::Data<RedisPool>,
) -> AuthService {
    let user_repo = UserRepository::new(pool.get_ref().clone());
    let refresh_token_repo = RefreshTokenRepository::new(pool.get_ref().clone());
    let blacklist_repo = TokenBlacklistRepository::new(pool.get_ref().clone());
    let cache = AuthCache::new(redis.get_ref().clone());

    // TODO: Get these from configuration
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-super-secret-jwt-key-change-this-in-production".to_string());
    let jwt_access_expiration_hours = std::env::var("JWT_ACCESS_EXPIRATION_HOURS")
        .unwrap_or_else(|_| "24".to_string())
        .parse::<i64>()
        .unwrap_or(24);
    let jwt_refresh_expiration_days = std::env::var("JWT_REFRESH_EXPIRATION_DAYS")
        .unwrap_or_else(|_| "30".to_string())
        .parse::<i64>()
        .unwrap_or(30);

    AuthService::new(
        user_repo,
        refresh_token_repo,
        blacklist_repo,
        cache,
        jwt_secret,
        jwt_access_expiration_hours,
        jwt_refresh_expiration_days,
    )
}

// ===== AUTH ENDPOINTS =====

// POST /api/v1/auth/register
pub async fn register(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    request: web::Json<RegisterRequest>
) -> impl Responder {
    let auth_service = create_auth_service(&pool, &redis);

    match auth_service.register(request.into_inner()).await {
        Ok(response) => HttpResponse::Created().json(response),
        Err(AuthError::UserAlreadyExists) => HttpResponse::Conflict().json(ErrorResponse {
            error: "UserAlreadyExists".to_string(),
            message: Some("A user with this email already exists".to_string()),
        }),
        Err(AuthError::InvalidCredentials) => HttpResponse::BadRequest().json(ErrorResponse {
            error: "WeakPassword".to_string(),
            message: Some("Password must be at least 8 characters long".to_string()),
        }),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "RegistrationFailed".to_string(),
            message: Some("Failed to register user".to_string()),
        }),
    }
}

// POST /api/v1/auth/login
pub async fn login(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    request: web::Json<LoginRequest>
) -> impl Responder {
    let auth_service = create_auth_service(&pool, &redis);

    match auth_service.login(request.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(AuthError::InvalidCredentials) => HttpResponse::Unauthorized().json(ErrorResponse {
            error: "InvalidCredentials".to_string(),
            message: Some("Invalid email or password".to_string()),
        }),
        Err(AuthError::TooManyLoginAttempts) => HttpResponse::TooManyRequests().json(ErrorResponse {
            error: "TooManyLoginAttempts".to_string(),
            message: Some("Too many failed login attempts. Try again later".to_string()),
        }),
        Err(AuthError::EmailNotVerified) => HttpResponse::Forbidden().json(ErrorResponse {
            error: "EmailNotVerified".to_string(),
            message: Some("Please verify your email before logging in".to_string()),
        }),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "LoginFailed".to_string(),
            message: Some("Failed to authenticate user".to_string()),
        }),
}
}

// POST /api/v1/auth/refresh
pub async fn refresh_token(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    request: web::Json<RefreshTokenRequest>
) -> impl Responder {
    let auth_service = create_auth_service(&pool, &redis);

    match auth_service.refresh_token(request.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(AuthError::InvalidToken) => HttpResponse::Unauthorized().json(ErrorResponse {
            error: "InvalidRefreshToken".to_string(),
            message: Some("Invalid or expired refresh token".to_string()),
        }),
        Err(AuthError::UserNotFound) => HttpResponse::Unauthorized().json(ErrorResponse {
            error: "UserNotFound".to_string(),
            message: Some("User associated with token not found".to_string()),
        }),
        Err(e) => {
            eprintln!("Token refresh failed: {:?}", e);
            HttpResponse::InternalServerError().json(ErrorResponse {
                error: "TokenRefreshFailed".to_string(),
                message: Some("Failed to refresh token".to_string()),
            })
        }
}
}

// POST /api/v1/auth/logout
pub async fn logout(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    req: HttpRequest,
    request: web::Json<LogoutRequest>
) -> impl Responder {
    // Extract and validate JWT token
    let auth_header = req.headers().get("Authorization");

    if auth_header.is_none() {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "MissingAuthorizationHeader".to_string(),
            message: Some("Authorization header is required".to_string()),
        });
    }

    let auth_str = match auth_header.unwrap().to_str() {
        Ok(s) => s,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidAuthorizationHeader".to_string(),
                message: Some("Invalid authorization header format".to_string()),
            });
        }
    };

    if !auth_str.starts_with("Bearer ") {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "InvalidAuthorizationFormat".to_string(),
            message: Some("Authorization header must be in 'Bearer <token>' format".to_string()),
        });
    }

    let token = &auth_str[7..]; // Remove "Bearer " prefix

    let auth_service = create_auth_service(&pool, &redis);

    // Validate token and extract user ID
    let claims = match auth_service.validate_token(token).await {
        Ok(claims) => claims,
        Err(AuthError::TokenExpired) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenExpired".to_string(),
                message: Some("Access token has expired".to_string()),
            });
        },
        Err(AuthError::TokenBlacklisted) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenRevoked".to_string(),
                message: Some("Token has been revoked".to_string()),
            });
        },
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidToken".to_string(),
                message: Some("Invalid or malformed access token".to_string()),
            });
        }
    };

    let user_id = match uuid::Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidTokenClaims".to_string(),
                message: Some("Invalid user ID in token".to_string()),
            });
        }
    };

    // NOTE: logout invalidates refresh token server-side; access token revocation is handled
    // by short TTL on access tokens. If you want immediate access-token revocation too,
    // extend AuthService::logout to accept (token, claims.exp) and blacklist it.
    match auth_service.logout(request.into_inner(), user_id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Successfully logged out"
        })),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "LogoutFailed".to_string(),
            message: Some("Failed to logout".to_string()),
        }),
    }
}

// GET /api/v1/auth/verify-email/{token}
pub async fn verify_email(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    path: web::Path<String>
) -> impl Responder {
    let token = path.into_inner();
    let auth_service = create_auth_service(&pool, &redis);

    match auth_service.verify_email(&token).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Email verified successfully"
        })),
        Err(AuthError::InvalidVerificationToken) => HttpResponse::BadRequest().json(ErrorResponse {
            error: "InvalidVerificationToken".to_string(),
            message: Some("Invalid or expired verification token".to_string()),
        }),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "VerificationFailed".to_string(),
            message: Some("Failed to verify email".to_string()),
        }),
}
}

// POST /api/v1/auth/password-reset
pub async fn request_password_reset(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    request: web::Json<RequestPasswordResetRequest>
) -> impl Responder {
    let auth_service = create_auth_service(&pool, &redis);

    match auth_service.request_password_reset(request.into_inner()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "If the email exists, a password reset link has been sent"
        })),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "PasswordResetFailed".to_string(),
            message: Some("Failed to request password reset".to_string()),
        }),
    }
}

// POST /api/v1/auth/password-reset/confirm
pub async fn reset_password(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    request: web::Json<ResetPasswordRequest>
) -> impl Responder {
    let auth_service = create_auth_service(&pool, &redis);

    match auth_service.reset_password(request.into_inner()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Password reset successfully"
        })),
        Err(AuthError::InvalidToken) => HttpResponse::BadRequest().json(ErrorResponse {
            error: "InvalidResetToken".to_string(),
            message: Some("Invalid or expired reset token".to_string()),
        }),
        Err(AuthError::InvalidCredentials) => HttpResponse::BadRequest().json(ErrorResponse {
            error: "WeakPassword".to_string(),
            message: Some("Password must be at least 8 characters long".to_string()),
        }),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "PasswordResetFailed".to_string(),
            message: Some("Failed to reset password".to_string()),
        }),
}
}

// ===== USER ENDPOINTS =====

// GET /api/v1/user/profile
pub async fn get_profile(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    req: HttpRequest
) -> impl Responder {
    // Extract and validate JWT token
    let auth_header = req.headers().get("Authorization");

    if auth_header.is_none() {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "MissingAuthorizationHeader".to_string(),
            message: Some("Authorization header is required".to_string()),
        });
    }

    let auth_str = match auth_header.unwrap().to_str() {
        Ok(s) => s,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidAuthorizationHeader".to_string(),
                message: Some("Invalid authorization header format".to_string()),
            });
        }
    };

    if !auth_str.starts_with("Bearer ") {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "InvalidAuthorizationFormat".to_string(),
            message: Some("Authorization header must be in 'Bearer <token>' format".to_string()),
        });
    }

    let token = &auth_str[7..]; // Remove "Bearer " prefix

    let auth_service = create_auth_service(&pool, &redis);

    // Validate token and extract user ID
    let claims = match auth_service.validate_token(token).await {
        Ok(claims) => claims,
        Err(AuthError::TokenExpired) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenExpired".to_string(),
                message: Some("Access token has expired".to_string()),
            });
        },
        Err(AuthError::TokenBlacklisted) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenRevoked".to_string(),
                message: Some("Token has been revoked".to_string()),
            });
        },
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidToken".to_string(),
                message: Some("Invalid or malformed access token".to_string()),
            });
        }
    };

    let user_id = match uuid::Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidTokenClaims".to_string(),
                message: Some("Invalid user ID in token".to_string()),
            });
        }
    };

    match auth_service.get_profile(user_id).await {
        Ok(profile) => HttpResponse::Ok().json(profile),
        Err(AuthError::UserNotFound) => HttpResponse::NotFound().json(ErrorResponse {
            error: "UserNotFound".to_string(),
            message: Some("User profile not found".to_string()),
        }),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "ProfileFetchFailed".to_string(),
            message: Some("Failed to fetch user profile".to_string()),
        }),
}
}

// PUT /api/v1/user/profile
pub async fn update_profile(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    req: HttpRequest,
    request: web::Json<UpdateProfileRequest>
) -> impl Responder {
    // Extract and validate JWT token
    let auth_header = req.headers().get("Authorization");

    if auth_header.is_none() {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "MissingAuthorizationHeader".to_string(),
            message: Some("Authorization header is required".to_string()),
        });
    }

    let auth_str = match auth_header.unwrap().to_str() {
        Ok(s) => s,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidAuthorizationHeader".to_string(),
                message: Some("Invalid authorization header format".to_string()),
            });
        }
    };

    if !auth_str.starts_with("Bearer ") {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "InvalidAuthorizationFormat".to_string(),
            message: Some("Authorization header must be in 'Bearer <token>' format".to_string()),
        });
    }

    let token = &auth_str[7..]; // Remove "Bearer " prefix

    let auth_service = create_auth_service(&pool, &redis);

    // Validate token and extract user ID
    let claims = match auth_service.validate_token(token).await {
        Ok(claims) => claims,
        Err(AuthError::TokenExpired) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenExpired".to_string(),
                message: Some("Access token has expired".to_string()),
            });
        },
        Err(AuthError::TokenBlacklisted) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenRevoked".to_string(),
                message: Some("Token has been revoked".to_string()),
            });
        },
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidToken".to_string(),
                message: Some("Invalid or malformed access token".to_string()),
            });
        }
    };

    let user_id = match uuid::Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidTokenClaims".to_string(),
                message: Some("Invalid user ID in token".to_string()),
            });
        }
    };

    match auth_service.update_profile(user_id, request.into_inner()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Profile updated successfully"
        })),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "ProfileUpdateFailed".to_string(),
            message: Some("Failed to update profile".to_string()),
        }),
}
}

// POST /api/v1/user/change-password
pub async fn change_password(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    req: HttpRequest,
    request: web::Json<ChangePasswordRequest>
) -> impl Responder {
    // Extract and validate JWT token
    let auth_header = req.headers().get("Authorization");

    if auth_header.is_none() {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "MissingAuthorizationHeader".to_string(),
            message: Some("Authorization header is required".to_string()),
        });
    }

    let auth_str = match auth_header.unwrap().to_str() {
        Ok(s) => s,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidAuthorizationHeader".to_string(),
                message: Some("Invalid authorization header format".to_string()),
            });
        }
    };

    if !auth_str.starts_with("Bearer ") {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "InvalidAuthorizationFormat".to_string(),
            message: Some("Authorization header must be in 'Bearer <token>' format".to_string()),
        });
    }

    let token = &auth_str[7..]; // Remove "Bearer " prefix

    let auth_service = create_auth_service(&pool, &redis);

    // Validate token and extract user ID
    let claims = match auth_service.validate_token(token).await {
        Ok(claims) => claims,
        Err(AuthError::TokenExpired) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenExpired".to_string(),
                message: Some("Access token has expired".to_string()),
            });
        },
        Err(AuthError::TokenBlacklisted) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenRevoked".to_string(),
                message: Some("Token has been revoked".to_string()),
            });
        },
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidToken".to_string(),
                message: Some("Invalid or malformed access token".to_string()),
            });
        }
    };

    let user_id = match uuid::Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidTokenClaims".to_string(),
                message: Some("Invalid user ID in token".to_string()),
            });
        }
    };

    match auth_service.change_password(user_id, request.into_inner()).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Password changed successfully"
        })),
        Err(AuthError::InvalidCredentials) => HttpResponse::BadRequest().json(ErrorResponse {
            error: "InvalidCurrentPassword".to_string(),
            message: Some("Current password is incorrect".to_string()),
        }),
        Err(AuthError::UserNotFound) => HttpResponse::NotFound().json(ErrorResponse {
            error: "UserNotFound".to_string(),
            message: Some("User not found".to_string()),
        }),
        Err(_) => HttpResponse::InternalServerError().json(ErrorResponse {
            error: "PasswordChangeFailed".to_string(),
            message: Some("Failed to change password".to_string()),
        }),
    }
}

// ===== ADMIN ENDPOINTS =====

// GET /api/v1/admin/users
pub async fn admin_get_users(
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    req: HttpRequest
) -> impl Responder {
    // Extract and validate JWT token
    let auth_header = req.headers().get("Authorization");

    if auth_header.is_none() {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "MissingAuthorizationHeader".to_string(),
            message: Some("Authorization header is required".to_string()),
        });
    }

    let auth_str = match auth_header.unwrap().to_str() {
        Ok(s) => s,
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidAuthorizationHeader".to_string(),
                message: Some("Invalid authorization header format".to_string()),
            });
        }
    };

    if !auth_str.starts_with("Bearer ") {
        return HttpResponse::Unauthorized().json(ErrorResponse {
            error: "InvalidAuthorizationFormat".to_string(),
            message: Some("Authorization header must be in 'Bearer <token>' format".to_string()),
        });
    }

    let token = &auth_str[7..]; // Remove "Bearer " prefix

    let auth_service = create_auth_service(&pool, &redis);

    // Validate token and check admin role
    let claims = match auth_service.validate_token(token).await {
        Ok(claims) => claims,
        Err(AuthError::TokenExpired) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenExpired".to_string(),
                message: Some("Access token has expired".to_string()),
            });
        },
        Err(AuthError::TokenBlacklisted) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "TokenRevoked".to_string(),
                message: Some("Token has been revoked".to_string()),
            });
        },
        Err(_) => {
            return HttpResponse::Unauthorized().json(ErrorResponse {
                error: "InvalidToken".to_string(),
                message: Some("Invalid or malformed access token".to_string()),
            });
        }
    };

    // Check if user has admin role
    if claims.role != "admin" {
        return HttpResponse::Forbidden().json(ErrorResponse {
            error: "InsufficientPermissions".to_string(),
            message: Some("Admin role required for this endpoint".to_string()),
        });
    }

    // This would require additional admin-specific logic
    // For now, just return a placeholder
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Admin endpoints - user management coming soon",
        "status": "under_development",
        "admin_user": claims.email
    }))
}
