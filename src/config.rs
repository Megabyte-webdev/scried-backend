use std::{env, path::PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    pub app_env: String,
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub access_token_ttl_seconds: i64,
    pub refresh_token_ttl_days: i64,
    pub database_max_connections: u32,
    pub cors_allowed_origins: Vec<String>,
    pub private_storage_dir: PathBuf,
    pub max_upload_bytes: usize,
    pub trust_proxy_headers: bool,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let cors_allowed_origins = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();

        let jwt_secret = required("JWT_SECRET")?;
        anyhow::ensure!(jwt_secret.as_bytes().len() >= 32, "JWT_SECRET must be at least 32 bytes");

        let max_upload_bytes = env::var("MAX_UPLOAD_BYTES")
            .unwrap_or_else(|_| "5242880".to_string()).parse::<usize>()?;
        anyhow::ensure!(max_upload_bytes > 0 && max_upload_bytes <= 5 * 1024 * 1024, "MAX_UPLOAD_BYTES must be between 1 byte and 5 MiB");

        Ok(Self {
            app_env: env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse()?,
            database_url: required("DATABASE_URL")?,
            redis_url: required("REDIS_URL")?,
            jwt_secret,
            jwt_issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "https://api.scried.example".to_string()),
            jwt_audience: env::var("JWT_AUDIENCE").unwrap_or_else(|_| "scried-clients".to_string()),
            access_token_ttl_seconds: env::var("ACCESS_TOKEN_TTL_SECONDS").unwrap_or_else(|_| "900".to_string()).parse()?,
            refresh_token_ttl_days: env::var("REFRESH_TOKEN_TTL_DAYS").unwrap_or_else(|_| "30".to_string()).parse()?,
            database_max_connections: env::var("DATABASE_MAX_CONNECTIONS").unwrap_or_else(|_| "30".to_string()).parse()?,
            cors_allowed_origins,
            private_storage_dir: PathBuf::from(env::var("PRIVATE_STORAGE_DIR").unwrap_or_else(|_| "./var/private".to_string())),
            max_upload_bytes,
            trust_proxy_headers: env::var("TRUST_PROXY_HEADERS").map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false),
        })
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = env::var(name).map_err(|_| anyhow::anyhow!("required environment variable {name} is missing"))?;
    anyhow::ensure!(!value.trim().is_empty(), "required environment variable {name} is empty");
    Ok(value)
}
