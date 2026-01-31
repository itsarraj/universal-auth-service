use crate::{DbPool, RedisPool};
use crate::module::health::model::HealthState;

pub async fn check_database(pool: &DbPool) -> Result<HealthState, Box<dyn std::error::Error + Send + Sync>> {
    match sqlx::query("SELECT 1").fetch_one(pool).await {
        Ok(_) => Ok(HealthState::Healthy),
        Err(e) => Err(Box::new(e))
    }
}

pub async fn check_authentication(pool: &DbPool) -> Result<HealthState, Box<dyn std::error::Error + Send + Sync>> {
    // todo: update the sql later when the authentication service is implemented
    match sqlx::query("SELECT 1").fetch_one(pool).await {
        Ok(_) => Ok(HealthState::Healthy),
        Err(e) => Err(Box::new(e))
    }
}

pub async fn check_redis(redis_pool: &RedisPool) -> Result<HealthState, Box<dyn std::error::Error + Send + Sync>> {
    let mut conn = redis_pool.clone();
    match redis::cmd("PING").query_async::<String>(&mut conn).await {
        Ok(_) => Ok(HealthState::Healthy),
        Err(e) => Err(Box::new(e))
    }
}
