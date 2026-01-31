use sqlx::PgPool;
use uuid::Uuid;
use chrono::{DateTime, Utc, NaiveDateTime};
use crate::module::auth::model::{User, RefreshToken, AuthError};

pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_user(&self, user: &User) -> Result<User, AuthError> {
        let row = sqlx::query(
            "INSERT INTO users (id, email, password_hash, name, role, email_verified, email_verification_token)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, email, password_hash, name, role, email_verified, email_verification_token, password_reset_token, password_reset_expires_at, created_at, updated_at"
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(&user.name)
        .bind(&user.role)
        .bind(user.email_verified)
        .bind(&user.email_verification_token)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        User::from_row(&row).map_err(|e| AuthError::DatabaseError(e.to_string()))
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let user = User::from_row(&row).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
                Ok(Some(user))
            },
            None => Ok(None),
        }
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError> {
        let row = sqlx::query("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let user = User::from_row(&row).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
                Ok(Some(user))
            },
            None => Ok(None),
        }
    }

    pub async fn find_by_verification_token(&self, token: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query("SELECT * FROM users WHERE email_verification_token = $1")
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let user = User::from_row(&row).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
                Ok(Some(user))
            },
            None => Ok(None),
        }
    }

    pub async fn find_by_password_reset_token(&self, token: &str) -> Result<Option<User>, AuthError> {
        let row = sqlx::query(
            "SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_expires_at > $2"
        )
        .bind(token)
        .bind(Utc::now())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let user = User::from_row(&row).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
                Ok(Some(user))
            },
            None => Ok(None),
        }
    }

    pub async fn update_email_verified(&self, user_id: Uuid, verified: bool) -> Result<(), AuthError> {
        sqlx::query("UPDATE users SET email_verified = $1, email_verification_token = NULL WHERE id = $2")
            .bind(verified)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub async fn update_password_reset_token(&self, user_id: Uuid, token: &str, expires_at: DateTime<Utc>) -> Result<(), AuthError> {
        sqlx::query("UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2 WHERE id = $3")
            .bind(token)
            .bind(expires_at)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), AuthError> {
        sqlx::query("UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires_at = NULL WHERE id = $2")
            .bind(password_hash)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub async fn update_profile(&self, user_id: Uuid, name: Option<&str>, email: Option<&str>) -> Result<(), AuthError> {
        if name.is_some() || email.is_some() {
            let mut query = "UPDATE users SET ".to_string();
            let mut params = Vec::new();
            let mut param_count = 1;

            if let Some(name_val) = name {
                query.push_str(&format!("name = ${}, ", param_count));
                params.push(name_val);
                param_count += 1;
            }

            if let Some(email_val) = email {
                query.push_str(&format!("email = ${}, ", param_count));
                params.push(email_val);
                param_count += 1;
            }

            // Remove trailing comma and space
            query.truncate(query.len() - 2);
            query.push_str(&format!(" WHERE id = ${}", param_count));

            let mut sql_query = sqlx::query(&query);
            for param in params {
                sql_query = sql_query.bind(param);
            }
            sql_query = sql_query.bind(user_id);

            sql_query.execute(&self.pool)
                .await
                .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        }
        Ok(())
    }
}

pub struct RefreshTokenRepository {
    pool: PgPool,
}

impl RefreshTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, token: &RefreshToken) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)"
        )
        .bind(token.id)
        .bind(token.user_id)
        .bind(&token.token_hash)
        .bind(token.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub async fn find_by_hash(&self, token_hash: &str) -> Result<Option<RefreshToken>, AuthError> {
        let row = sqlx::query("SELECT * FROM refresh_tokens WHERE token_hash = $1 AND expires_at > $2")
            .bind(token_hash)
            .bind(Utc::now().naive_utc())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let token = RefreshToken::from_row(&row).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
                Ok(Some(token))
            },
            None => Ok(None),
        }
    }

    pub async fn delete_by_user_id(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub async fn delete_by_hash(&self, token_hash: &str) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM refresh_tokens WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

pub struct TokenBlacklistRepository {
    pool: PgPool,
}

impl TokenBlacklistRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn add_to_blacklist(&self, token_hash: &str, expires_at: NaiveDateTime) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO token_blacklist (id, token_hash, expires_at) VALUES ($1, $2, $3)"
        )
        .bind(Uuid::new_v4())
        .bind(token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub async fn is_blacklisted(&self, token_hash: &str) -> Result<bool, AuthError> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM token_blacklist WHERE token_hash = $1 AND expires_at > $2"
        )
        .bind(token_hash)
        .bind(Utc::now().naive_utc())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(count.0 > 0)
    }

    pub async fn cleanup_expired(&self) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM token_blacklist WHERE expires_at <= $1")
            .bind(Utc::now().naive_utc())
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}