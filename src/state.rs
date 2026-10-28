use crate::{config::Config, proof_storage::ProofStorage};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: ConnectionManager,
    pub config: Arc<Config>,
    pub proof_storage: ProofStorage,
}

impl AppState {
    pub fn new(db: PgPool, redis: ConnectionManager, config: Config, proof_storage: ProofStorage) -> Self {
        Self { db, redis, config: Arc::new(config), proof_storage }
    }
}
