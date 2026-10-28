use crate::{error::AppError, middleware::CurrentUser, rbac, security::{hash_token, new_opaque_token}, state::AppState};
use axum::{extract::{Path, State}, Extension, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct CreateProgram {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub school_name: Option<String>,
    pub state: Option<String>,
    pub start_at: Option<DateTime<Utc>>,
    pub end_at: Option<DateTime<Utc>>,
    pub status: Option<String>,
}
#[derive(Deserialize)]
pub struct CreateEvent {
    pub name: String,
    pub description: Option<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: Option<DateTime<Utc>>,
    pub checkin_opens_at: Option<DateTime<Utc>>,
    pub checkin_closes_at: Option<DateTime<Utc>>,
}
#[derive(Deserialize)]
pub struct CheckInRequest { pub qr_token: String }
#[derive(Deserialize)]
pub struct PaperCheckInRequest {
    pub email: String,
    pub note: Option<String>,
    pub method: Option<String>,
}

pub async fn create_program(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Json(input): Json<CreateProgram>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["program_manager", "admin"]).await?;
    if input.name.trim().is_empty() || input.name.len() > 200 { return Err(AppError::Validation("Program name must be 1–200 characters".to_string())); }
    if input.slug.trim().is_empty() || input.slug.len() > 180 || !input.slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(AppError::Validation("Slug must use lowercase letters, numbers and hyphens".to_string()));
    }
    if input.start_at.as_ref().zip(input.end_at.as_ref()).is_some_and(|(start,end)| end < start) { return Err(AppError::Validation("end_at must not be before start_at".to_string())); }
    let status = input.status.as_deref().unwrap_or("draft");
    if !["draft","published","completed","archived"].contains(&status) { return Err(AppError::Validation("Invalid program status".to_string())); }
    let row = sqlx::query("INSERT INTO programs(name,slug,description,school_name,state,start_at,end_at,status,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,name,slug,status,created_at")
        .bind(input.name.trim()).bind(input.slug.trim()).bind(input.description.unwrap_or_default()).bind(input.school_name).bind(input.state).bind(input.start_at).bind(input.end_at).bind(status).bind(actor.user_id)
        .fetch_one(&state.db).await.map_err(map_conflict)?;
    let id: Uuid = row.try_get("id").map_err(|_| AppError::Internal)?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'program.created','program',$2,'{}'::jsonb)")
        .bind(actor.user_id).bind(id.to_string()).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"id":id,"name":row.try_get::<String,_>("name").map_err(|_| AppError::Internal)?,"slug":row.try_get::<String,_>("slug").map_err(|_| AppError::Internal)?,"status":row.try_get::<String,_>("status").map_err(|_| AppError::Internal)?,"created_at":row.try_get::<DateTime<Utc>,_>("created_at").map_err(|_| AppError::Internal)?}})))
}

pub async fn create_event(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path(program_id): Path<Uuid>,
    Json(input): Json<CreateEvent>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["program_manager", "admin"]).await?;
    if input.name.trim().is_empty() || input.name.len() > 200 { return Err(AppError::Validation("Event name must be 1–200 characters".to_string())); }
    if input.ends_at.as_ref().is_some_and(|end| end < &input.starts_at) { return Err(AppError::Validation("ends_at must not be before starts_at".to_string())); }
    if input.checkin_closes_at.as_ref().zip(input.checkin_opens_at.as_ref()).is_some_and(|(close,open)| close < open) { return Err(AppError::Validation("checkin_closes_at must not be before checkin_opens_at".to_string())); }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM programs WHERE id=$1 AND status <> 'archived')")
        .bind(program_id).fetch_one(&state.db).await?;
    if !exists { return Err(AppError::NotFound); }
    let qr_token = new_opaque_token();
    let row = sqlx::query("INSERT INTO events(program_id,name,description,starts_at,ends_at,checkin_opens_at,checkin_closes_at,qr_token_hash,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,name,starts_at,status")
        .bind(program_id).bind(input.name.trim()).bind(input.description.unwrap_or_default()).bind(input.starts_at).bind(input.ends_at).bind(input.checkin_opens_at).bind(input.checkin_closes_at).bind(hash_token(&qr_token)).bind(actor.user_id)
        .fetch_one(&state.db).await?;
    let event_id: Uuid = row.try_get("id").map_err(|_| AppError::Internal)?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'event.created','event',$2,'{}'::jsonb)")
        .bind(actor.user_id).bind(event_id.to_string()).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"id":event_id,"program_id":program_id,"name":row.try_get::<String,_>("name").map_err(|_| AppError::Internal)?,"starts_at":row.try_get::<DateTime<Utc>,_>("starts_at").map_err(|_| AppError::Internal)?,"status":row.try_get::<String,_>("status").map_err(|_| AppError::Internal)?,"qr_token":qr_token,"qr_instruction":"Render a QR code containing this event ID and token. Show the token only to authorised staff when creating the event."}})))
}

pub async fn check_in(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(event_id): Path<Uuid>,
    Json(input): Json<CheckInRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if input.qr_token.len() < 40 || input.qr_token.len() > 64 { return Err(AppError::BadRequest("Invalid event QR token")); }
    let row = sqlx::query("SELECT qr_token_hash,status,starts_at,checkin_opens_at,checkin_closes_at FROM events WHERE id=$1")
        .bind(event_id).fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    let stored: Vec<u8> = row.try_get("qr_token_hash").map_err(|_| AppError::Internal)?;
    let provided = hash_token(&input.qr_token);
    if stored.as_slice().ct_eq(provided.as_slice()).unwrap_u8() != 1 { return Err(AppError::Unauthorized); }
    let status: String = row.try_get("status").map_err(|_| AppError::Internal)?;
    let starts_at: DateTime<Utc> = row.try_get("starts_at").map_err(|_| AppError::Internal)?;
    let opens: Option<DateTime<Utc>> = row.try_get("checkin_opens_at").map_err(|_| AppError::Internal)?;
    let closes: Option<DateTime<Utc>> = row.try_get("checkin_closes_at").map_err(|_| AppError::Internal)?;
    let now = Utc::now();
    if status == "cancelled" || status == "completed" || now < opens.unwrap_or(starts_at) || closes.is_some_and(|v| now > v) { return Err(AppError::Conflict); }
    let row = sqlx::query("INSERT INTO event_checkins(event_id,user_id,method) VALUES ($1,$2,'qr') ON CONFLICT(event_id,user_id) DO NOTHING RETURNING id,checked_in_at")
        .bind(event_id).bind(user.user_id).fetch_optional(&state.db).await?;
    if let Some(row) = row {
        sqlx::query("UPDATE applications a SET stage='guided',updated_at=now() WHERE a.user_id=$1 AND a.stage='registered' AND EXISTS(SELECT 1 FROM events e JOIN program_opportunities po ON po.program_id=e.program_id WHERE e.id=$2 AND po.opportunity_id=a.opportunity_id)")
            .bind(user.user_id).bind(event_id).execute(&state.db).await?;
        sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'event.checked_in','event_checkin',$2,$3)")
            .bind(user.user_id).bind(event_id.to_string()).bind(json!({"method":"qr"})).execute(&state.db).await?;
        Ok(Json(json!({"status":"success","message":"Check-in recorded","data":{"event_id":event_id,"checked_in_at":row.try_get::<DateTime<Utc>,_>("checked_in_at").map_err(|_| AppError::Internal)?,"already_checked_in":false}})))
    } else {
        let checked_in_at: DateTime<Utc> = sqlx::query_scalar("SELECT checked_in_at FROM event_checkins WHERE event_id=$1 AND user_id=$2")
            .bind(event_id).bind(user.user_id).fetch_one(&state.db).await?;
        Ok(Json(json!({"status":"success","message":"Already checked in","data":{"event_id":event_id,"checked_in_at":checked_in_at,"already_checked_in":true}})))
    }
}

pub async fn paper_check_in(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path(event_id): Path<Uuid>,
    Json(input): Json<PaperCheckInRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["verifier", "program_manager", "admin"]).await?;
    let email = input.email.trim().to_lowercase();
    if !email.contains('@') || email.len() > 254 { return Err(AppError::Validation("Enter a valid student email".to_string())); }
    let event_exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM events WHERE id=$1 AND status <> 'cancelled')")
        .bind(event_id).fetch_one(&state.db).await?;
    if !event_exists { return Err(AppError::NotFound); }
    let student_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE email_normalized=$1 AND status='active' AND deleted_at IS NULL")
        .bind(&email).fetch_optional(&state.db).await?;
    let Some(student_id) = student_id else { return Err(AppError::NotFound); };
    let method = input.method.as_deref().unwrap_or("paper_sheet");
    if !["paper_sheet", "staff_manual"].contains(&method) { return Err(AppError::Validation("Invalid check-in method".to_string())); }
    let result = sqlx::query("INSERT INTO event_checkins(event_id,user_id,method,recorded_by,note) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(event_id,user_id) DO NOTHING RETURNING id,checked_in_at")
        .bind(event_id).bind(student_id).bind(method).bind(actor.user_id).bind(input.note.as_deref()).fetch_optional(&state.db).await?;
    if result.is_some() {
        sqlx::query("UPDATE applications a SET stage='guided',updated_at=now() WHERE a.user_id=$1 AND a.stage='registered' AND EXISTS(SELECT 1 FROM events e JOIN program_opportunities po ON po.program_id=e.program_id WHERE e.id=$2 AND po.opportunity_id=a.opportunity_id)")
            .bind(student_id).bind(event_id).execute(&state.db).await?;
    }
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'event.paper_check_in','event',$2,$3)")
        .bind(actor.user_id).bind(event_id.to_string()).bind(json!({"student_id":student_id,"method":method})).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"event_id":event_id,"student_id":student_id,"created":result.is_some(),"checked_in_at":result.and_then(|r| r.try_get::<DateTime<Utc>,_>("checked_in_at").ok())}})))
}

fn map_conflict(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_error) = &error { if db_error.code().as_deref() == Some("23505") { return AppError::Conflict; } }
    AppError::Database(error)
}
pub async fn link_opportunity(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path((program_id, opportunity_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["program_manager", "admin"]).await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM programs WHERE id=$1 AND status <> 'archived') AND EXISTS(SELECT 1 FROM opportunities WHERE id=$2 AND status <> 'archived')")
        .bind(program_id).bind(opportunity_id).fetch_one(&state.db).await?;
    if !exists { return Err(AppError::NotFound); }
    sqlx::query("INSERT INTO program_opportunities(program_id,opportunity_id,created_by) VALUES ($1,$2,$3) ON CONFLICT(program_id,opportunity_id) DO NOTHING")
        .bind(program_id).bind(opportunity_id).bind(actor.user_id).execute(&state.db).await?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'program.opportunity_linked','program',$2,$3)")
        .bind(actor.user_id).bind(program_id.to_string()).bind(json!({"opportunity_id":opportunity_id})).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"program_id":program_id,"opportunity_id":opportunity_id}})))
}
