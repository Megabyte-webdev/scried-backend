use crate::{error::AppError, security::decode_access_token, state::AppState};
use axum::{extract::{Request, State}, http::header, middleware::Next, response::Response};
use sqlx::Row;
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct CurrentUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub email: String,
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let header_value = request.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).ok_or(AppError::Unauthorized)?;
    let token = header_value.strip_prefix("Bearer ").ok_or(AppError::Unauthorized)?;
    let claims = decode_access_token(token, &state.config)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
    let session_id = Uuid::parse_str(&claims.sid).map_err(|_| AppError::Unauthorized)?;

    let row = sqlx::query(
        "SELECT u.id, u.email, u.auth_version, u.status FROM user_sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1 AND s.user_id = $2 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.deleted_at IS NULL"
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else { return Err(AppError::Unauthorized); };
    let version: i64 = row.try_get("auth_version").map_err(|_| AppError::Internal)?;
    let status: String = row.try_get("status").map_err(|_| AppError::Internal)?;
    if version != claims.ver || status != "active" { return Err(AppError::Unauthorized); }
    let email: String = row.try_get("email").map_err(|_| AppError::Internal)?;
    request.extensions_mut().insert(CurrentUser { user_id, session_id, email });
    Ok(next.run(request).await)
}

/// Redis-backed per-IP throttling for authentication and guest application endpoints.
/// Only the TCP peer IP is used; X-Forwarded-For must not be trusted from arbitrary clients.
pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();
    let auth_limited = ["/auth/register", "/auth/login", "/auth/refresh", "/auth/verify-email", "/auth/request-password-reset", "/auth/reset-password", "/auth/claim-guest-applications"]
        .iter().any(|suffix| path.ends_with(suffix));
    let protected_rate = auth_limited || path.ends_with("/applications/guest") || path.contains("/applications/guest/") || path.ends_with("/check-in");
    if protected_rate {
        let ip = peer_ip(&request, state.config.trust_proxy_headers).map(|value| value.to_string()).unwrap_or_else(|| "unresolved-peer".to_string());
        let key = format!("scried:ratelimit:{}:{}", ip, route_bucket(&path, &method));
        let (limit, window_secs) = if auth_limited { (12_i64, 60_i64) } else { (30_i64, 60_i64) };
        let mut redis = state.redis.clone();
        let count: i64 = redis::Script::new("local n = redis.call('INCR', KEYS[1]); if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return n")
            .key(&key).arg(window_secs).invoke_async(&mut redis).await.map_err(|e| {
                tracing::error!(error = %e, "redis rate limiter unavailable");
                AppError::Unavailable
            })?;
        if count > limit { return Err(AppError::TooManyRequests); }
    }
    Ok(next.run(request).await)
}

fn peer_ip(request: &Request, trust_proxy_headers: bool) -> Option<IpAddr> {
    if trust_proxy_headers {
        if let Some(ip) = request.headers().get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .and_then(|value| value.trim().parse::<IpAddr>().ok()) {
            return Some(ip);
        }
    }
    request.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>().map(|i| i.0.ip())
}

fn route_bucket(path: &str, method: &http::Method) -> &'static str {
    if path.ends_with("/login") { "login" }
    else if path.ends_with("/register") { "register" }
    else if path.ends_with("/refresh") { "refresh" }
    else if path.ends_with("/request-password-reset") { "reset_request" }
    else if path.ends_with("/reset-password") { "reset" }
    else if path.ends_with("/verify-email") { "verify" }
    else if path.ends_with("/applications/guest") && *method == http::Method::POST { "guest_application" }
    else if path.contains("/check-in") { "checkin" }
    else { "auth_other" }
}
