use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: HealthState, 
    pub timestamp: DateTime<Utc>,
    pub version: String,
    pub uptime: u64, // in seconds
    pub components: Vec<ComponentHealth>,
}   

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthState,
    pub message: Option<String>,
    pub response_time_ms: Option<u64>, // in milliseconds
    pub last_checked: Option<DateTime<Utc>>,
}

impl ComponentHealth {
    pub fn new(name: String, status: HealthState, message: Option<String>, response_time_ms: Option<u64>, last_checked: Option<DateTime<Utc>>) -> Self {
        Self { name, status, message, response_time_ms, last_checked }
    }
}

impl Default for ComponentHealth {
    fn default() -> Self {
        Self::new("unknown".to_string(), HealthState::Unknown, None, None, None)
    }
}