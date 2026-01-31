use std::time::Instant;

use actix_web::{HttpResponse, Responder, web};
use chrono::{DateTime, Utc};
use crate::{DbPool, RedisPool};
use crate::module::health::model::{HealthStatus, HealthState, ComponentHealth};
use crate::module::health::service::{check_database, check_authentication, check_redis};

static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

pub async fn health_status(pool: web::Data<DbPool>, redis_pool: web::Data<RedisPool>) -> impl Responder {
    let now: DateTime<Utc> = chrono::Utc::now();
    let version = env!("CARGO_PKG_VERSION").to_string();
    let start_time = START_TIME.get_or_init(|| Instant::now());
    let uptime = start_time.elapsed().as_secs();

    // Check database
    let database_start = Instant::now();
    let database_status = match check_database(&pool).await {
        Ok(status) => status,
        Err(_) => HealthState::Unhealthy
    };
    let database_response_time = database_start.elapsed();
    
    // Check authentication (using database for now)
    let auth_start = Instant::now();
    let authentication_status = match check_authentication(&pool).await {
        Ok(status) => status,
        Err(_) => HealthState::Unhealthy
    };
    let authentication_response_time = auth_start.elapsed();

    // Check Redis
    let redis_start = Instant::now();
    let redis_status = match check_redis(&redis_pool).await {
        Ok(status) => status,
        Err(_) => HealthState::Unhealthy
    };
    let redis_response_time = redis_start.elapsed();

    let components = vec![
        ComponentHealth::new(
            "database".to_string(),
            database_status.clone(),
            None,
            Some(database_response_time.as_millis() as u64),
            Some(now)
        ),
        ComponentHealth::new(
            "authentication".to_string(),
            authentication_status.clone(),
            None,
            Some(authentication_response_time.as_millis() as u64),
            Some(now)
        ),
        ComponentHealth::new(
            "redis".to_string(),
            redis_status.clone(),
            None,
            Some(redis_response_time.as_millis() as u64),
            Some(now)
        )
    ];

    // Determine overall health status
    let overall_status = if database_status == HealthState::Healthy
        && authentication_status == HealthState::Healthy
        && redis_status == HealthState::Healthy {
        HealthState::Healthy
    } else if database_status == HealthState::Unhealthy
        || authentication_status == HealthState::Unhealthy
        || redis_status == HealthState::Unhealthy {
        HealthState::Unhealthy
    } else {
        HealthState::Degraded
    };

    let health_status = HealthStatus {
        status: overall_status,
        timestamp: now,
        version: version,
        uptime: uptime,
        components: components
    };

    HttpResponse::Ok().json(&health_status)
}