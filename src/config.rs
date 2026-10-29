use std::{ env, path::PathBuf };
use url::Url;

#[derive(Clone, Debug)]
pub struct EmailConfig {
    pub resend_api_key: Option<String>,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub from: String,
    pub frontend_base_url: Url,
}

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
    pub proof_storage: ProofStorageConfig,
    pub max_upload_bytes: usize,
    pub trust_proxy_headers: bool,
    pub email: Option<EmailConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofStorageConfig {
    Local,
    Cloudinary {
        cloud_name: String,
        api_key: String,
        api_secret: String,
    },
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let cors_allowed_origins = env
            ::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();

        let jwt_secret = required("JWT_SECRET")?;
        anyhow::ensure!(jwt_secret.as_bytes().len() >= 32, "JWT_SECRET must be at least 32 bytes");

        let max_upload_bytes = env
            ::var("MAX_UPLOAD_BYTES")
            .unwrap_or_else(|_| "5242880".to_string())
            .parse::<usize>()?;
        anyhow::ensure!(
            max_upload_bytes > 0 && max_upload_bytes <= 5 * 1024 * 1024,
            "MAX_UPLOAD_BYTES must be between 1 byte and 5 MiB"
        );
        let proof_storage = match
            env
                ::var("STORAGE_BACKEND")
                .unwrap_or_else(|_| "local".to_string())
                .as_str()
        {
            "local" => ProofStorageConfig::Local,
            "cloudinary" => {
                let value = required("CLOUDINARY_URL")?;
                let url = Url::parse(&value).map_err(|_|
                    anyhow::anyhow!("CLOUDINARY_URL must be a valid Cloudinary connection URL")
                )?;
                anyhow::ensure!(
                    url.scheme() == "cloudinary",
                    "CLOUDINARY_URL must use the cloudinary scheme"
                );
                let cloud_name = url
                    .host_str()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("CLOUDINARY_URL must include a cloud name"))?;
                let api_key = url.username();
                let api_secret = url.password().unwrap_or_default();
                anyhow::ensure!(
                    !api_key.is_empty() && !api_secret.is_empty(),
                    "CLOUDINARY_URL must include the API key and secret"
                );
                anyhow::ensure!(
                    (url.path().is_empty() || url.path() == "/") &&
                        url.query().is_none() &&
                        url.fragment().is_none(),
                    "CLOUDINARY_URL must not include a path, query, or fragment"
                );
                ProofStorageConfig::Cloudinary {
                    cloud_name: cloud_name.to_string(),
                    api_key: api_key.to_string(),
                    api_secret: api_secret.to_string(),
                }
            }
            _ => anyhow::bail!("STORAGE_BACKEND must be either local or cloudinary"),
        };
        let email = EmailConfig::from_env()?;

        Ok(Self {
            app_env: env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env
                ::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
            database_url: required("DATABASE_URL")?,
            redis_url: required("REDIS_URL")?,
            jwt_secret,
            jwt_issuer: env
                ::var("JWT_ISSUER")
                .unwrap_or_else(|_| "https://api.scried.example".to_string()),
            jwt_audience: env::var("JWT_AUDIENCE").unwrap_or_else(|_| "scried-clients".to_string()),
            access_token_ttl_seconds: env
                ::var("ACCESS_TOKEN_TTL_SECONDS")
                .unwrap_or_else(|_| "900".to_string())
                .parse()?,
            refresh_token_ttl_days: env
                ::var("REFRESH_TOKEN_TTL_DAYS")
                .unwrap_or_else(|_| "30".to_string())
                .parse()?,
            database_max_connections: env
                ::var("DATABASE_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "30".to_string())
                .parse()?,
            cors_allowed_origins,
            private_storage_dir: PathBuf::from(
                env::var("PRIVATE_STORAGE_DIR").unwrap_or_else(|_| "./var/private".to_string())
            ),
            proof_storage,
            max_upload_bytes,
            trust_proxy_headers: env
                ::var("TRUST_PROXY_HEADERS")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            email,
        })
    }
}

impl EmailConfig {
    fn from_env() -> anyhow::Result<Option<Self>> {
        let provider_settings = [
            "RESEND_API_KEY",
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_USERNAME",
            "SMTP_PASSWORD",
        ];
        let configured = provider_settings.iter().any(|name| {
            env::var(name).map(|value| !value.trim().is_empty()).unwrap_or(false)
        });
        if !configured {
            return Ok(None);
        }

        let frontend_base_url = Url::parse(&required("FRONTEND_BASE_URL")?)?;
        anyhow::ensure!(
            matches!(frontend_base_url.scheme(), "http" | "https") && frontend_base_url.host_str().is_some(),
            "FRONTEND_BASE_URL must be an absolute HTTP or HTTPS URL"
        );

        let smtp_port = required("SMTP_PORT")?.parse::<u16>()?;
        anyhow::ensure!(smtp_port > 0, "SMTP_PORT must be greater than zero");

        Ok(Some(Self {
            resend_api_key: env::var("RESEND_API_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            smtp_host: required("SMTP_HOST")?,
            smtp_port,
            smtp_username: required("SMTP_USERNAME")?,
            smtp_password: required("SMTP_PASSWORD")?,
            from: required("EMAIL_FROM")?,
            frontend_base_url,
        }))
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = env
        ::var(name)
        .map_err(|_| anyhow::anyhow!("required environment variable {name} is missing"))?;
    anyhow::ensure!(!value.trim().is_empty(), "required environment variable {name} is empty");
    Ok(value)
}
