use scried_backend::{build_router, config::Config, proof_storage::ProofStorage, state::AppState};
use sqlx::postgres::PgPoolOptions;
use std::{net::SocketAddr, time::Duration};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("scried_backend=info,tower_http=info")))
        .with_target(false)
        .init();

    let config = Config::from_env()?;
    anyhow::ensure!(config.access_token_ttl_seconds > 0, "ACCESS_TOKEN_TTL_SECONDS must be positive");
    anyhow::ensure!(config.refresh_token_ttl_days > 0, "REFRESH_TOKEN_TTL_DAYS must be positive");
    let db = PgPoolOptions::new()
        .max_connections(config.database_max_connections.clamp(5, 100))
        .acquire_timeout(Duration::from_secs(5))
        .max_lifetime(Duration::from_secs(30 * 60))
        .idle_timeout(Duration::from_secs(5 * 60))
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&db).await?;

    let redis_client = redis::Client::open(config.redis_url.clone())?;
    let redis = redis::aio::ConnectionManager::new(redis_client).await?;
    let proof_storage = ProofStorage::new(&config)?;
    proof_storage.initialize().await?;

    if let Some(email_config) = config.email.clone() {
        let worker = scried_backend::email::EmailDeliveryWorker::new(email_config)?;
        let email_db = db.clone();
        tokio::spawn(async move {
            worker.run(email_db).await;
        });
        tracing::info!("email outbox worker started");
    } else {
        tracing::warn!("email delivery is disabled; configure Resend and SMTP settings to deliver outbox messages");
    }

    let host = config.host.clone();
    let port = config.port;
    let state = AppState::new(db, redis, config, proof_storage);
    let retention_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5 * 60));
        loop {
            interval.tick().await;
            match scried_backend::proofs::cleanup_expired(&retention_state).await {
                Ok(count) if count > 0 => tracing::info!(cleaned = count, "expired proof files cleaned"),
                Ok(_) => {},
                Err(error) => tracing::error!(error = %error, "proof-retention worker failed"),
            }
        }
    });
    let app = build_router(state)?;
    let address: SocketAddr = format!("{host}:{port}").parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(address = %listener.local_addr()?, "Scried API listening");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
