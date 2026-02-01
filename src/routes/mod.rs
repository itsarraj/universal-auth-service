use actix_web::web;
use std::sync::Arc;

use crate::module::health::handler::health_status;
use crate::module::auth::{
    handler::*,
    service::AuthService,
    repository::{UserRepository, RefreshTokenRepository, TokenBlacklistRepository},
    cache::AuthCache,
};
use crate::module::email::service::EmailService;
use crate::{DbPool, RedisPool};

pub fn config(
    cfg: &mut web::ServiceConfig,
    pool: web::Data<DbPool>,
    redis: web::Data<RedisPool>,
    jwt_config: crate::configuration::JwtSettings,
    email_config: crate::configuration::EmailSettings,
) {
    // Create shared email service
    let email_service = EmailService::new(
        email_config.api_key.clone(),
        email_config.from_email.clone(),
        email_config.from_name.clone(),
        email_config.base_url.clone(),
    );

    // Create shared auth service
    let user_repo = UserRepository::new(pool.get_ref().clone());
    let refresh_token_repo = RefreshTokenRepository::new(pool.get_ref().clone());
    let blacklist_repo = TokenBlacklistRepository::new(pool.get_ref().clone());
    let cache = AuthCache::new(redis.get_ref().clone());

    let auth_service = Arc::new(AuthService::new(
        user_repo,
        refresh_token_repo,
        blacklist_repo,
        cache,
        email_service,
        jwt_config.secret.clone(),
        jwt_config.access_token_expiration_hours,
        jwt_config.refresh_token_expiration_days,
    ));
    
    cfg.service(
        web::scope("/api/v1")
        // Health checks (public)
        .route("/health", web::get().to(health_status))

            // Auth endpoints (public)
            .service(
                web::scope("/auth")
                    .app_data(web::Data::new(Arc::clone(&auth_service)))
                    .route("/register", web::post().to(register))
                    .route("/login", web::post().to(login))
                    .route("/refresh", web::post().to(refresh_token))
                    .route("/logout", web::post().to(logout))
                    .route("/verify-email/{token}", web::get().to(verify_email))
                    .route("/password-reset", web::post().to(request_password_reset))
                    .route("/password-reset/confirm", web::post().to(reset_password))
            )

            // Protected user endpoints
            .service(
                web::scope("/user")
                    .app_data(web::Data::new(Arc::clone(&auth_service)))
                    .route("/profile", web::get().to(get_profile))
                    .route("/profile", web::put().to(update_profile))
                    .route("/change-password", web::post().to(change_password))
            )

            // Admin-only endpoints (require admin role)
            .service(
                web::scope("/admin")
                    .app_data(web::Data::new(Arc::clone(&auth_service)))
                    .route("/users", web::get().to(admin_get_users))
            )
    );
}
