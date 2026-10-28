use crate::{error::AppError, middleware::CurrentUser, state::AppState};
use sqlx::Row;

pub async fn roles_for(state: &AppState, user_id: uuid::Uuid) -> Result<Vec<String>, AppError> {
    let rows = sqlx::query("SELECT role_code FROM user_roles WHERE user_id = $1 ORDER BY role_code")
        .bind(user_id)
        .fetch_all(&state.db)
        .await?;
    Ok(rows.into_iter().filter_map(|row| row.try_get::<String, _>("role_code").ok()).collect())
}

pub async fn require_any_role(state: &AppState, user: &CurrentUser, allowed: &[&str]) -> Result<Vec<String>, AppError> {
    let roles = roles_for(state, user.user_id).await?;
    if roles.iter().any(|role| allowed.contains(&role.as_str())) {
        Ok(roles)
    } else {
        Err(AppError::Forbidden)
    }
}
