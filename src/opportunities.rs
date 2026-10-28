use crate::{error::AppError, middleware::CurrentUser, rbac, state::AppState};
use axum::{extract::{Path, Query, State}, Extension, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct ListQuery {
    pub page: Option<i64>,
    pub page_size: Option<i64>,
    pub category: Option<String>,
    pub status: Option<String>,
    pub search: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateOpportunity {
    pub title: String,
    pub slug: String,
    pub summary: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub official_url: String,
    pub application_deadline: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub partner_name: Option<String>,
    pub value_ngn: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateOpportunity {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub official_url: Option<String>,
    pub application_deadline: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub partner_name: Option<String>,
    pub value_ngn: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/opportunities",
    tag = "Opportunities",
    summary = "List published opportunities",
    params(
        ("page" = Option<i64>, Query, description = "Page number, starting at 1"),
        ("page_size" = Option<i64>, Query, description = "Page size, up to 50"),
        ("category" = Option<String>, Query),
        ("search" = Option<String>, Query)
    ),
    responses((status = 200, description = "Published opportunities returned"))
)]
pub async fn list_public(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 50);
    let offset = (page - 1) * page_size;
    let search = query.search.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let category = query.category.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let rows = sqlx::query(
        "SELECT id,title,slug,summary,description,category,official_url,application_deadline,partner_name,value_ngn,created_at FROM opportunities WHERE status='published' AND (application_deadline IS NULL OR application_deadline > now()) AND ($1::text IS NULL OR category=$1) AND ($2::text IS NULL OR title ILIKE '%' || $2 || '%' OR summary ILIKE '%' || $2 || '%') ORDER BY application_deadline ASC NULLS LAST, created_at DESC LIMIT $3 OFFSET $4"
    )
    .bind(category).bind(search).bind(page_size).bind(offset).fetch_all(&state.db).await?;
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM opportunities WHERE status='published' AND (application_deadline IS NULL OR application_deadline > now()) AND ($1::text IS NULL OR category=$1) AND ($2::text IS NULL OR title ILIKE '%' || $2 || '%' OR summary ILIKE '%' || $2 || '%')"
    ).bind(category).bind(search).fetch_one(&state.db).await?;
    let items = rows.into_iter().map(|row| {
        json!({
            "id": row.try_get::<Uuid,_>("id").ok(),
            "title": row.try_get::<String,_>("title").ok(),
            "slug": row.try_get::<String,_>("slug").ok(),
            "summary": row.try_get::<String,_>("summary").ok(),
            "description": row.try_get::<String,_>("description").ok(),
            "category": row.try_get::<String,_>("category").ok(),
            "official_url": row.try_get::<String,_>("official_url").ok(),
            "application_deadline": row.try_get::<Option<DateTime<Utc>>,_>("application_deadline").ok().flatten(),
            "partner_name": row.try_get::<Option<String>,_>("partner_name").ok().flatten(),
            "value_ngn": row.try_get::<Option<i64>,_>("value_ngn").ok().flatten(),
            "created_at": row.try_get::<DateTime<Utc>,_>("created_at").ok()
        })
    }).collect::<Vec<_>>();
    Ok(Json(json!({"status":"success","data":{"items":items,"page":page,"page_size":page_size,"total":total}})))
}

#[utoipa::path(get, path = "/api/v1/opportunities/{slug}", tag = "Opportunities", summary = "Get a published opportunity", params(("slug" = String, Path)), responses((status = 200, description = "Opportunity details returned")))]
pub async fn get_public(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query(
        "SELECT id,title,slug,summary,description,category,official_url,application_deadline,partner_name,value_ngn,created_at FROM opportunities WHERE slug=$1 AND status='published' AND (application_deadline IS NULL OR application_deadline > now())"
    ).bind(slug).fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    Ok(Json(json!({"status":"success","data":{
        "id": row.try_get::<Uuid,_>("id").map_err(|_| AppError::Internal)?,
        "title": row.try_get::<String,_>("title").map_err(|_| AppError::Internal)?,
        "slug": row.try_get::<String,_>("slug").map_err(|_| AppError::Internal)?,
        "summary": row.try_get::<String,_>("summary").map_err(|_| AppError::Internal)?,
        "description": row.try_get::<String,_>("description").map_err(|_| AppError::Internal)?,
        "category": row.try_get::<String,_>("category").map_err(|_| AppError::Internal)?,
        "official_url": row.try_get::<String,_>("official_url").map_err(|_| AppError::Internal)?,
        "application_deadline": row.try_get::<Option<DateTime<Utc>>,_>("application_deadline").map_err(|_| AppError::Internal)?,
        "partner_name": row.try_get::<Option<String>,_>("partner_name").map_err(|_| AppError::Internal)?,
        "value_ngn": row.try_get::<Option<i64>,_>("value_ngn").map_err(|_| AppError::Internal)?,
        "created_at": row.try_get::<DateTime<Utc>,_>("created_at").map_err(|_| AppError::Internal)?
    }})))
}

#[utoipa::path(post, path = "/api/v1/admin/opportunities", tag = "Opportunities", summary = "Create an opportunity", request_body = CreateOpportunity, security(("bearerAuth" = [])), responses((status = 200, description = "Opportunity created")))]
pub async fn create(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Json(input): Json<CreateOpportunity>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["program_manager", "admin"]).await?;
    validate_opportunity(&input.title, &input.slug, &input.summary, &input.official_url, input.value_ngn, input.status.as_deref())?;
    let status = input.status.as_deref().unwrap_or("draft");
    let row = sqlx::query(
        "INSERT INTO opportunities(title,slug,summary,description,category,official_url,application_deadline,status,partner_name,value_ngn,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,title,slug,status,created_at"
    )
    .bind(input.title.trim()).bind(input.slug.trim().to_lowercase()).bind(input.summary.trim())
    .bind(input.description.unwrap_or_default()).bind(input.category.unwrap_or_else(|| "general".to_string()))
    .bind(input.official_url.trim()).bind(input.application_deadline).bind(status)
    .bind(input.partner_name).bind(input.value_ngn).bind(actor.user_id)
    .fetch_one(&state.db).await.map_err(map_conflict)?;
    let id: Uuid = row.try_get("id").map_err(|_| AppError::Internal)?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'opportunity.created','opportunity',$2,$3)")
        .bind(actor.user_id).bind(id.to_string()).bind(json!({"slug":input.slug,"status":status})).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"id":id,"title":row.try_get::<String,_>("title").map_err(|_| AppError::Internal)?,"slug":row.try_get::<String,_>("slug").map_err(|_| AppError::Internal)?,"status":row.try_get::<String,_>("status").map_err(|_| AppError::Internal)?,"created_at":row.try_get::<DateTime<Utc>,_>("created_at").map_err(|_| AppError::Internal)?}})))
}

#[utoipa::path(patch, path = "/api/v1/admin/opportunities/{opportunity_id}", tag = "Opportunities", summary = "Update an opportunity", params(("opportunity_id" = Uuid, Path)), request_body = UpdateOpportunity, security(("bearerAuth" = [])), responses((status = 200, description = "Opportunity updated")))]
pub async fn update(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path(opportunity_id): Path<Uuid>,
    Json(input): Json<UpdateOpportunity>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["program_manager", "admin"]).await?;
    if let Some(status) = input.status.as_deref() { validate_status(status)?; }
    if let Some(url) = input.official_url.as_deref() { validate_url(url)?; }
    if input.value_ngn.is_some_and(|v| v < 0) { return Err(AppError::Validation("value_ngn cannot be negative".to_string())); }
    let row = sqlx::query(
        "UPDATE opportunities SET title=COALESCE($2,title),summary=COALESCE($3,summary),description=COALESCE($4,description),official_url=COALESCE($5,official_url),application_deadline=COALESCE($6,application_deadline),status=COALESCE($7,status),partner_name=COALESCE($8,partner_name),value_ngn=COALESCE($9,value_ngn),updated_at=now() WHERE id=$1 RETURNING id,title,slug,status,updated_at"
    )
    .bind(opportunity_id).bind(input.title).bind(input.summary).bind(input.description).bind(input.official_url).bind(input.application_deadline).bind(input.status).bind(input.partner_name).bind(input.value_ngn)
    .fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'opportunity.updated','opportunity',$2,$3)")
        .bind(actor.user_id).bind(opportunity_id.to_string()).bind(json!({"fields_updated":true})).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"id":row.try_get::<Uuid,_>("id").map_err(|_| AppError::Internal)?,"title":row.try_get::<String,_>("title").map_err(|_| AppError::Internal)?,"slug":row.try_get::<String,_>("slug").map_err(|_| AppError::Internal)?,"status":row.try_get::<String,_>("status").map_err(|_| AppError::Internal)?,"updated_at":row.try_get::<DateTime<Utc>,_>("updated_at").map_err(|_| AppError::Internal)?}})))
}

fn validate_opportunity(title: &str, slug: &str, summary: &str, url: &str, value: Option<i64>, status: Option<&str>) -> Result<(), AppError> {
    if title.trim().is_empty() || title.len() > 200 { return Err(AppError::Validation("Title must be 1–200 characters".to_string())); }
    if slug.trim().is_empty() || slug.len() > 180 || !slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(AppError::Validation("Slug must use lowercase letters, numbers and hyphens".to_string()));
    }
    if summary.trim().is_empty() || summary.len() > 1000 { return Err(AppError::Validation("Summary must be 1–1000 characters".to_string())); }
    validate_url(url)?;
    if value.is_some_and(|v| v < 0) { return Err(AppError::Validation("value_ngn cannot be negative".to_string())); }
    if let Some(status) = status { validate_status(status)?; }
    Ok(())
}
fn validate_status(status: &str) -> Result<(), AppError> {
    if !["draft", "published", "archived"].contains(&status) { return Err(AppError::Validation("Invalid opportunity status".to_string())); }
    Ok(())
}
fn validate_url(url: &str) -> Result<(), AppError> {
    let url = url.trim().to_ascii_lowercase();
    if !(url.starts_with("https://") || (url.starts_with("http://localhost") && cfg!(debug_assertions))) || url.len() > 2048 {
        return Err(AppError::Validation("Official URL must be a valid HTTPS URL".to_string()));
    }
    Ok(())
}
fn map_conflict(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.code().as_deref() == Some("23505") { return AppError::Conflict; }
    }
    AppError::Database(error)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/opportunities",
    tag = "Opportunities",
    summary = "List opportunities for staff",
    params(
        ("page" = Option<i64>, Query, description = "Page number, starting at 1"),
        ("page_size" = Option<i64>, Query, description = "Page size, up to 100"),
        ("status" = Option<String>, Query, description = "Filter by draft, published, or archived"),
        ("search" = Option<String>, Query, description = "Search title or slug")
    ),
    security(("bearerAuth" = [])),
    responses((status = 200, description = "Opportunity records returned"))
)]
pub async fn list_admin(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Query(query): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["program_manager", "admin"]).await?;
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;
    let status_filter = query.status.as_deref().map(str::trim).filter(|s| ["draft", "published", "archived"].contains(s));
    let search = query.search.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let rows = sqlx::query("SELECT id,title,slug,summary,category,status,application_deadline,partner_name,value_ngn,created_at,updated_at FROM opportunities WHERE ($1::text IS NULL OR status=$1) AND ($2::text IS NULL OR title ILIKE '%'||$2||'%' OR slug ILIKE '%'||$2||'%') ORDER BY updated_at DESC LIMIT $3 OFFSET $4")
        .bind(status_filter).bind(search).bind(page_size).bind(offset).fetch_all(&state.db).await?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM opportunities WHERE ($1::text IS NULL OR status=$1) AND ($2::text IS NULL OR title ILIKE '%'||$2||'%' OR slug ILIKE '%'||$2||'%')")
        .bind(status_filter).bind(search).fetch_one(&state.db).await?;
    let items = rows.into_iter().map(|row| json!({
        "id":row.try_get::<Uuid,_>("id").ok(),"title":row.try_get::<String,_>("title").ok(),"slug":row.try_get::<String,_>("slug").ok(),
        "summary":row.try_get::<String,_>("summary").ok(),"category":row.try_get::<String,_>("category").ok(),"status":row.try_get::<String,_>("status").ok(),
        "application_deadline":row.try_get::<Option<DateTime<Utc>>,_>("application_deadline").ok().flatten(),"partner_name":row.try_get::<Option<String>,_>("partner_name").ok().flatten(),
        "value_ngn":row.try_get::<Option<i64>,_>("value_ngn").ok().flatten(),"created_at":row.try_get::<DateTime<Utc>,_>("created_at").ok(),"updated_at":row.try_get::<DateTime<Utc>,_>("updated_at").ok()
    })).collect::<Vec<_>>();
    Ok(Json(json!({"status":"success","data":{"items":items,"page":page,"page_size":page_size,"total":total}})))
}
