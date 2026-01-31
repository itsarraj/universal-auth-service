use redis::aio::ConnectionManager;
use uuid::Uuid;
use serde_json;
use crate::module::auth::model::{CachedUser, AuthError};

// ===== CACHE KEYS =====
const USER_CACHE_PREFIX: &str = "user:";
const LOGIN_ATTEMPTS_PREFIX: &str = "login_attempts:";
const BLACKLIST_PREFIX: &str = "blacklist:";

pub struct AuthCache {
    redis: ConnectionManager,
}

impl AuthCache {
    pub fn new(redis: ConnectionManager) -> Self {
        Self { redis }
    }

    // ===== USER CACHING =====

    pub async fn set_user(&self, user: &CachedUser) -> Result<(), AuthError> {
        let key = format!("{}{}", USER_CACHE_PREFIX, user.id);
        let json = serde_json::to_string(user)
            .map_err(|_| AuthError::CacheError("Serialization failed".to_string()))?;

        // Cache for 1 hour
        let _: () = redis::cmd("SETEX")
            .arg(&key)
            .arg(3600) // 1 hour TTL
            .arg(json)
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_user(&self, user_id: Uuid) -> Result<Option<CachedUser>, AuthError> {
        let key = format!("{}{}", USER_CACHE_PREFIX, user_id);
        let json: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        match json {
            Some(json) => {
                let user: CachedUser = serde_json::from_str(&json)
                    .map_err(|_| AuthError::CacheError("Deserialization failed".to_string()))?;
                Ok(Some(user))
            },
            None => Ok(None),
        }
    }

    pub async fn invalidate_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        let key = format!("{}{}", USER_CACHE_PREFIX, user_id);
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;
        Ok(())
    }

    // ===== RATE LIMITING =====

    pub async fn increment_login_attempts(&self, email: &str) -> Result<i64, AuthError> {
        let key = format!("{}{}", LOGIN_ATTEMPTS_PREFIX, email);
        let count: i64 = redis::cmd("INCR")
            .arg(&key)
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        // Set expiration if this is the first attempt
        if count == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(900) // 15 minutes
                .query_async(&mut self.redis.clone())
                .await
                .map_err(|e| AuthError::CacheError(e.to_string()))?;
        }

        Ok(count)
    }

    pub async fn get_login_attempts(&self, email: &str) -> Result<i64, AuthError> {
        let key = format!("{}{}", LOGIN_ATTEMPTS_PREFIX, email);
        let count: Option<i64> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        Ok(count.unwrap_or(0))
    }

    pub async fn reset_login_attempts(&self, email: &str) -> Result<(), AuthError> {
        let key = format!("{}{}", LOGIN_ATTEMPTS_PREFIX, email);
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;
        Ok(())
    }

    // ===== TOKEN BLACKLIST =====

    pub async fn add_to_blacklist(&self, token_hash: &str, expires_at: i64) -> Result<(), AuthError> {
        let key = format!("{}{}", BLACKLIST_PREFIX, token_hash);

        // Store with TTL until expiration
        let ttl_seconds = expires_at - chrono::Utc::now().timestamp();
        if ttl_seconds > 0 {
            let _: () = redis::cmd("SETEX")
                .arg(&key)
                .arg(ttl_seconds as usize)
                .arg("1") // Just store presence
                .query_async(&mut self.redis.clone())
                .await
                .map_err(|e| AuthError::CacheError(e.to_string()))?;
        }

        Ok(())
    }

    pub async fn is_blacklisted(&self, token_hash: &str) -> Result<bool, AuthError> {
        let key = format!("{}{}", BLACKLIST_PREFIX, token_hash);
        let exists: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        Ok(exists.is_some())
    }

    // ===== SESSION MANAGEMENT =====

    pub async fn set_session(&self, session_id: &str, user_id: Uuid, expires_in_seconds: i64) -> Result<(), AuthError> {
        let key = format!("session:{}", session_id);
        let _: () = redis::cmd("SETEX")
            .arg(&key)
            .arg(expires_in_seconds as usize)
            .arg(user_id.to_string())
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;
        Ok(())
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Option<Uuid>, AuthError> {
        let key = format!("session:{}", session_id);
        let user_id_str: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;

        match user_id_str {
            Some(id_str) => {
                let user_id = Uuid::parse_str(&id_str)
                    .map_err(|_| AuthError::CacheError("Invalid UUID in session".to_string()))?;
                Ok(Some(user_id))
            },
            None => Ok(None),
        }
    }

    pub async fn invalidate_session(&self, session_id: &str) -> Result<(), AuthError> {
        let key = format!("session:{}", session_id);
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;
        Ok(())
    }

    // ===== GENERAL CACHE UTILITIES =====

    pub async fn health_check(&self) -> Result<(), AuthError> {
        let _: String = redis::cmd("PING")
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;
        Ok(())
    }

    pub async fn cleanup_expired_keys(&self) -> Result<(), AuthError> {
        // Redis automatically expires keys with TTL, but we can manually clean up if needed
        // This is more of a maintenance operation
        let _: () = redis::cmd("PING")
            .query_async(&mut self.redis.clone())
            .await
            .map_err(|e| AuthError::CacheError(e.to_string()))?;
        Ok(())
    }
}