pub mod applications;
pub mod api_docs;
pub mod auth;
pub mod config;
pub mod error;
pub mod events;
pub mod middleware;
pub mod opportunities;
pub mod proofs;
pub mod reports;
pub mod rbac;
pub mod security;
pub mod state;

use axum::{
    middleware::from_fn_with_state,
    routing::{delete, get, post},
    Router,
};
use std::time::Duration;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
    set_header::SetResponseHeaderLayer,
};
use http::{header, HeaderValue, Method};
use crate::{middleware::{auth_middleware, rate_limit_middleware}, state::AppState};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub fn build_router(state: AppState) -> anyhow::Result<Router> {
    let allowed_origins = state.config.cors_allowed_origins
        .iter()
        .map(|origin| origin.parse::<HeaderValue>())
        .collect::<Result<Vec<_>, _>>()?;

    let public_api = Router::new()
        .route("/auth/register", post(auth::register))
        .route("/consent-documents/current", get(auth::current_consent_documents))
        .route("/auth/login", post(auth::login))
        .route("/auth/refresh", post(auth::refresh))
        .route("/auth/verify-email", post(auth::verify_email))
        .route("/auth/request-password-reset", post(auth::request_password_reset))
        .route("/auth/reset-password", post(auth::reset_password))
        .route("/opportunities", get(opportunities::list_public))
        .route("/opportunities/{slug}", get(opportunities::get_public))
        .route("/applications/guest", post(applications::create_guest))
        .route("/applications/guest/{application_id}/continue", post(applications::continue_guest))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        ;

    let protected_api = Router::new()
        .route("/auth/me", get(auth::me).patch(auth::update_me).delete(auth::delete_me))
        .route("/auth/me/export", get(auth::export_me))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/claim-guest-applications", post(applications::claim_guest_applications))
        .route("/applications", post(applications::create_authenticated))
        .route("/applications/me", get(applications::list_mine))
        .route("/applications/{application_id}", get(applications::get_one))
        .route("/applications/{application_id}/continue", post(applications::continue_authenticated))
        .route("/applications/{application_id}/proofs", post(proofs::upload))
        .route("/proofs/queue", get(proofs::queue))
        .route("/proofs/{proof_id}/download", get(proofs::download))
        .route("/proofs/{proof_id}/decision", post(proofs::decide))
        .route("/programs", post(events::create_program))
        .route("/programs/{program_id}/events", post(events::create_event))
        .route("/programs/{program_id}/opportunities/{opportunity_id}", post(events::link_opportunity))
        .route("/events/{event_id}/check-in", post(events::check_in))
        .route("/events/{event_id}/paper-check-ins", post(events::paper_check_in))
        .route("/admin/opportunities", get(opportunities::list_admin).post(opportunities::create))
        .route("/admin/consent-documents", post(auth::publish_consent_documents))
        .route("/admin/opportunities/{opportunity_id}", axum::routing::patch(opportunities::update))
        .route("/admin/users/{user_id}/roles", post(auth::assign_role))
        .route("/admin/users/{user_id}/roles/{role_code}", delete(auth::remove_role))
        .route("/admin/users/{user_id}/anonymise", post(auth::admin_anonymise_user))
        .route("/admin/audit-logs", get(auth::list_audit_logs))
        .route("/reports/opportunities/{opportunity_id}/funnel", get(reports::funnel))
        .route("/reports/opportunities/{opportunity_id}/applications.csv", get(reports::applications_csv))
        .route_layer(from_fn_with_state(state.clone(), auth_middleware));

    let app = Router::new()
        .merge(SwaggerUi::new("/docs").url("/api-docs/openapi.json", api_docs::ApiDoc::openapi()))
        .nest("/api/v1", public_api.merge(protected_api))
        .layer(from_fn_with_state(state.clone(), rate_limit_middleware))
        .layer(RequestBodyLimitLayer::new(5 * 1024 * 1024 + 128 * 1024))
        .layer(ConcurrencyLimitLayer::new(500))
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(SetResponseHeaderLayer::if_not_present(header::HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::if_not_present(header::HeaderName::from_static("x-frame-options"), HeaderValue::from_static("DENY")))
        .layer(SetResponseHeaderLayer::if_not_present(header::HeaderName::from_static("referrer-policy"), HeaderValue::from_static("no-referrer")))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(allowed_origins))
                .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE, Method::OPTIONS])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT, header::HeaderName::from_static("x-request-id")])
                .allow_credentials(false),
        )
        .with_state(state);

    Ok(app)
}

#[utoipa::path(
    get,
    path = "/api/v1/health/live",
    tag = "Health",
    summary = "Check API liveness",
    responses((status = 200, description = "The API process is running"))
)]
pub async fn health_live() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({"status":"ok"}))
}

#[utoipa::path(
    get,
    path = "/api/v1/health/ready",
    tag = "Health",
    summary = "Check API and dependency readiness",
    responses((status = 200, description = "PostgreSQL and Redis are available"))
)]
pub async fn health_ready(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<axum::Json<serde_json::Value>, crate::error::AppError> {
    sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.db).await?;
    let mut redis = state.redis.clone();
    let _: String = redis::cmd("PING").query_async(&mut redis).await.map_err(|_| crate::error::AppError::Unavailable)?;
    Ok(axum::Json(serde_json::json!({"status":"ready"})))
}
