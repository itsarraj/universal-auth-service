use actix_web::{App, HttpServer, web};

pub mod routes;
// pub mod db;
pub mod configuration;
pub mod module;
// pub mod middleware;
// pub mod health;
// pub mod utils;

use dotenvy::dotenv;
use redis::aio::ConnectionManager;
pub type DbPool = sqlx::PgPool;
pub type RedisPool = ConnectionManager;

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Starting MatchMyResume API...");

    // Load environment variables
    dotenv().ok();
    println!("🔧 Environment variables loaded from .env file");

    // Load application configuration
    let configuration = configuration::get_configuration().expect("Failed to load configuration");
    let database_url = configuration.database.connection_string();
    let redis_url = configuration.redis.connection_string();

    println!("📊 Database URL: {}", database_url);
    println!("🔴 Redis URL: {}", redis_url);

    // Establish database connection
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(100)
        .min_connections(5)
        .connect(&database_url).await?;

    println!("✅ Database connection established successfully!");
    println!("🔗 Connection Pool Info: {:#?}", pool);

    // Establish Redis connection
    let redis_client = redis::Client::open(redis_url)?;
    let redis_pool = ConnectionManager::new(redis_client).await?;

    println!("✅ Redis connection established successfully!");

    // Configure and start HTTP server
    println!("🔧 Starting API server on port {}", configuration.application_port);
    let jwt_config = configuration.jwt.clone();

    let _server = HttpServer::new(move || {
        App::new()
        // .wrap(Logger::default())
        // .wrap(middleware::cors::configure_cors())
        .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(redis_pool.clone()))
            .configure({
                let pool_data = web::Data::new(pool.clone());
                let redis_data = web::Data::new(redis_pool.clone());
                let jwt_config_clone = jwt_config.clone();
                let email_config_clone = configuration.email.clone();
                move |cfg| routes::config(cfg, pool_data, redis_data, jwt_config_clone, email_config_clone)
            })
    })
        .bind(format!("{}:{}", configuration.application_host, configuration.application_port))?
        .run()
    .await?;
    println!("🔧 API server stopped");
    Ok(())
}
