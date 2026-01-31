#[derive(serde::Deserialize)]
pub struct Settings {
    pub database: DatabaseSettings,
    pub redis: RedisSettings,
    pub jwt: JwtSettings,
    pub application_host: String,
    pub application_port: u16
}

#[derive(serde::Deserialize)]
pub struct DatabaseSettings {
    pub username: String,
    pub password: String,
    pub port: u16,
    pub host: String,
    pub database_name: String,
}

#[derive(serde::Deserialize)]
pub struct RedisSettings {
    pub host: String,
    pub port: u16,
    pub password: Option<String>,
    pub database: Option<u8>,
}

#[derive(serde::Deserialize, Clone)]
pub struct JwtSettings {
    pub secret: String,
    pub access_token_expiration_hours: i64,
    pub refresh_token_expiration_days: i64,
}

pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    // Initialise our configuration reader
    let settings = config ::Config::builder()
        // Add configuration values from a file named `configuration.yaml`.
        .add_source(
            config::File::new("configuration.yaml", config::FileFormat::Yaml)
        )
        .build()?;
    // Try to convert the configuration values it read into
    // our Settings type
    settings.try_deserialize::<Settings>()
}

impl DatabaseSettings {
    pub fn connection_string(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.database_name
        )
    }
}

impl RedisSettings {
    pub fn connection_string(&self) -> String {
        let mut conn_str = format!("redis://{}:{}", self.host, self.port);

        if let Some(password) = &self.password {
            conn_str = format!("redis://:{}@{}:{}", password, self.host, self.port);
        }

        if let Some(database) = self.database {
            conn_str = format!("{}/{}", conn_str, database);
        }

        conn_str
    }
}
