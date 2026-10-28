use crate::{error::AppError, middleware::CurrentUser, rbac, security::{hash_token, new_opaque_token}, state::AppState};
use axum::{extract::{Path, State}, Extension, Json};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub struct CreateApplication {
    pub opportunity_id: Uuid,
    pub full_name: Option<String>,
    pub whatsapp_number: Option<String>,
    pub school_name: Option<String>,
    pub state: Option<String>,
    pub faculty: Option<String>,
    pub department: Option<String>,
    pub course: Option<String>,
    pub level: Option<String>,
    pub age_range: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateGuestApplication {
    pub opportunity_id: Uuid,
    pub full_name: String,
    pub email: String,
    pub whatsapp_number: Option<String>,
    pub school_name: Option<String>,
    pub state: Option<String>,
    pub faculty: Option<String>,
    pub department: Option<String>,
    pub course: Option<String>,
    pub level: Option<String>,
    pub age_range: Option<String>,
    pub consent_accepted: bool,
    pub consent_version: String,
}

#[derive(Deserialize, ToSchema)]
pub struct GuestContinueRequest { pub access_token: String }

#[utoipa::path(post, path = "/api/v1/applications", tag = "Applications", summary = "Apply to an opportunity as the signed-in user", request_body = CreateApplication, security(("bearerAuth" = [])), responses((status = 200, description = "Application created")))]
pub async fn create_authenticated(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(input): Json<CreateApplication>,
) -> Result<Json<serde_json::Value>, AppError> {
    let opportunity = fetch_open_opportunity(&state, input.opportunity_id).await?;
    if let Some(age) = input.age_range.as_deref() { if !["under_18","18_20","21_24","25_29","30_plus","prefer_not_to_say"].contains(&age) { return Err(AppError::Validation("Invalid age range".to_string())); } }
    let profile = sqlx::query("SELECT u.email,u.full_name,p.whatsapp_number,p.school_name,p.state,p.faculty,p.department,p.course,p.level,p.age_range,p.matriculation_number FROM users u LEFT JOIN student_profiles p ON p.user_id=u.id WHERE u.id=$1 AND u.deleted_at IS NULL")
        .bind(user.user_id).fetch_optional(&state.db).await?;
    let Some(profile) = profile else { return Err(AppError::Unauthorized); };
    let email: String = profile.try_get("email").map_err(|_| AppError::Internal)?;
    let profile_full_name: String = profile.try_get("full_name").map_err(|_| AppError::Internal)?;
    let full_name = input.full_name.as_deref().filter(|s| !s.trim().is_empty()).unwrap_or(profile_full_name.as_str()).to_string();
    let snapshot = json!({
        "full_name": full_name,
        "email": email.clone(),
        "whatsapp_number": input.whatsapp_number.or(profile.try_get("whatsapp_number").ok().flatten()),
        "school_name": input.school_name.or(profile.try_get("school_name").ok().flatten()),
        "state": input.state.or(profile.try_get("state").ok().flatten()),
        "faculty": input.faculty.or(profile.try_get("faculty").ok().flatten()),
        "department": input.department.or(profile.try_get("department").ok().flatten()),
        "course": input.course.or(profile.try_get("course").ok().flatten()),
        "level": input.level.or(profile.try_get("level").ok().flatten()),
        "age_range": input.age_range.or(profile.try_get("age_range").ok().flatten()),
        "matriculation_number": profile.try_get::<Option<String>,_>("matriculation_number").ok().flatten()
    });
    let row = sqlx::query("INSERT INTO applications(opportunity_id,user_id,email,email_normalized,registration_snapshot,stage) VALUES ($1,$2,$3,lower($3),$4,CASE WHEN EXISTS(SELECT 1 FROM event_checkins c JOIN events e ON e.id=c.event_id JOIN program_opportunities po ON po.program_id=e.program_id WHERE c.user_id=$2 AND po.opportunity_id=$1) THEN 'guided' ELSE 'registered' END) RETURNING id,stage,registered_at")
        .bind(input.opportunity_id).bind(user.user_id).bind(&email).bind(snapshot).fetch_one(&state.db).await.map_err(map_conflict)?;
    let application_id: Uuid = row.try_get("id").map_err(|_| AppError::Internal)?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'application.created','application',$2,$3)")
        .bind(user.user_id).bind(application_id.to_string()).bind(json!({"opportunity_id":input.opportunity_id,"source":"authenticated"})).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"application_id":application_id,"opportunity_id":input.opportunity_id,"opportunity_title":opportunity.0,"stage":row.try_get::<String,_>("stage").map_err(|_| AppError::Internal)?,"registered_at":row.try_get::<chrono::DateTime<Utc>,_>("registered_at").map_err(|_| AppError::Internal)?}})))
}

#[utoipa::path(post, path = "/api/v1/applications/guest", tag = "Applications", summary = "Create a guest application", request_body = CreateGuestApplication, responses((status = 200, description = "Guest application and continuation token created")))]
pub async fn create_guest(
    State(state): State<AppState>,
    Json(input): Json<CreateGuestApplication>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (opportunity_title, _) = fetch_open_opportunity(&state, input.opportunity_id).await?;
    let email = normalize_email(&input.email)?;
    if input.full_name.trim().len() < 2 || input.full_name.trim().len() > 160 { return Err(AppError::Validation("Full name must be 2–160 characters".to_string())); }
    if let Some(age) = input.age_range.as_deref() { if !["under_18","18_20","21_24","25_29","30_plus","prefer_not_to_say"].contains(&age) { return Err(AppError::Validation("Invalid age range".to_string())); } }
    if !input.consent_accepted { return Err(AppError::Validation("Acceptance of the current privacy notice and terms is required before applying".to_string())); }
    let consent_version = input.consent_version.trim();
    if consent_version.is_empty() || consent_version.len() > 100 || !consent_version.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err(AppError::Validation("A valid consent wording version is required".to_string()));
    }
    let token = new_opaque_token();
    let snapshot = json!({
        "full_name":input.full_name.trim(),"email":email.clone(),"whatsapp_number":input.whatsapp_number,"school_name":input.school_name,
        "state":input.state,"faculty":input.faculty,"department":input.department,"course":input.course,"level":input.level,"age_range":input.age_range
    });
    let mut tx = state.db.begin().await?;
    let consent_rows = sqlx::query("SELECT consent_type,wording_snapshot FROM consent_documents WHERE version=$1 AND is_current=true FOR SHARE")
        .bind(consent_version).fetch_all(&mut *tx).await?;
    let privacy_wording = consent_rows.iter()
        .find(|row| row.try_get::<String, _>("consent_type").ok().as_deref() == Some("privacy_notice"))
        .and_then(|row| row.try_get::<String, _>("wording_snapshot").ok())
        .ok_or(AppError::Conflict)?;
    let terms_wording = consent_rows.iter()
        .find(|row| row.try_get::<String, _>("consent_type").ok().as_deref() == Some("terms"))
        .and_then(|row| row.try_get::<String, _>("wording_snapshot").ok())
        .ok_or(AppError::Conflict)?;
    let row = sqlx::query("INSERT INTO applications(opportunity_id,email,email_normalized,registration_snapshot,guest_access_token_hash) VALUES ($1,$2,$2,$3,$4) RETURNING id,registered_at")
        .bind(input.opportunity_id).bind(&email).bind(snapshot).bind(hash_token(&token)).fetch_one(&mut *tx).await.map_err(map_conflict)?;
    let application_id: Uuid = row.try_get("id").map_err(|_| AppError::Internal)?;
    sqlx::query("INSERT INTO consents(application_id,email_normalized,consent_type,wording_version,wording_snapshot,accepted) VALUES ($1,$2,'privacy_notice',$3,$4,true),($1,$2,'terms',$3,$5,true)")
        .bind(application_id).bind(&email).bind(consent_version).bind(&privacy_wording).bind(&terms_wording).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit_logs(action,entity_type,entity_id,metadata) VALUES ('application.guest_created','application',$1,$2)")
        .bind(application_id.to_string()).bind(json!({"opportunity_id":input.opportunity_id})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"success","data":{"application_id":application_id,"opportunity_title":opportunity_title,"registered_at":row.try_get::<chrono::DateTime<Utc>,_>("registered_at").map_err(|_| AppError::Internal)?,"guest_access_token":token,"message":"Save this token securely; it is required to continue to the official opportunity link."}})))
}

#[utoipa::path(post, path = "/api/v1/applications/{application_id}/continue", tag = "Applications", summary = "Continue to the official opportunity as the owner", params(("application_id" = Uuid, Path)), security(("bearerAuth" = [])), responses((status = 200, description = "Official opportunity URL returned")))]
pub async fn continue_authenticated(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(application_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query("SELECT a.opportunity_id,o.official_url,o.title,o.status,o.application_deadline FROM applications a JOIN opportunities o ON o.id=a.opportunity_id WHERE a.id=$1 AND a.user_id=$2 AND a.status='active'")
        .bind(application_id).bind(user.user_id).fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    let status: String = row.try_get("status").map_err(|_| AppError::Internal)?;
    let deadline: Option<chrono::DateTime<Utc>> = row.try_get("application_deadline").map_err(|_| AppError::Internal)?;
    if status != "published" || deadline.is_some_and(|d| d <= Utc::now()) { return Err(AppError::Conflict); }
    let url: String = row.try_get("official_url").map_err(|_| AppError::Internal)?;
    let click_row = sqlx::query("UPDATE applications SET clicked_through_at=COALESCE(clicked_through_at,now()),updated_at=now() WHERE id=$1 RETURNING clicked_through_at")
        .bind(application_id).fetch_one(&state.db).await?;
    let clicked_through_at: chrono::DateTime<Utc> = click_row.try_get("clicked_through_at").map_err(|_| AppError::Internal)?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'application.click_through','application',$2,'{}'::jsonb)")
        .bind(user.user_id).bind(application_id.to_string()).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"application_id":application_id,"official_url":url,"clicked_through_at":clicked_through_at}})))
}

#[utoipa::path(post, path = "/api/v1/applications/guest/{application_id}/continue", tag = "Applications", summary = "Continue a guest application to the official opportunity", params(("application_id" = Uuid, Path)), request_body = GuestContinueRequest, responses((status = 200, description = "Official opportunity URL returned")))]
pub async fn continue_guest(
    State(state): State<AppState>,
    Path(application_id): Path<Uuid>,
    Json(input): Json<GuestContinueRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if input.access_token.len() < 40 || input.access_token.len() > 64 { return Err(AppError::Unauthorized); }
    let row = sqlx::query("SELECT a.guest_access_token_hash,o.official_url,o.title,o.status,o.application_deadline FROM applications a JOIN opportunities o ON o.id=a.opportunity_id WHERE a.id=$1 AND a.user_id IS NULL AND a.status='active'")
        .bind(application_id).fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    let stored: Option<Vec<u8>> = row.try_get("guest_access_token_hash").map_err(|_| AppError::Internal)?;
    let provided = hash_token(&input.access_token);
    if !stored.as_ref().is_some_and(|value| value.as_slice().ct_eq(provided.as_slice()).unwrap_u8() == 1) { return Err(AppError::Unauthorized); }
    let status: String = row.try_get("status").map_err(|_| AppError::Internal)?;
    let deadline: Option<chrono::DateTime<Utc>> = row.try_get("application_deadline").map_err(|_| AppError::Internal)?;
    if status != "published" || deadline.is_some_and(|d| d <= Utc::now()) { return Err(AppError::Conflict); }
    let url: String = row.try_get("official_url").map_err(|_| AppError::Internal)?;
    let click_row = sqlx::query("UPDATE applications SET clicked_through_at=COALESCE(clicked_through_at,now()),updated_at=now() WHERE id=$1 AND guest_access_token_hash=$2 RETURNING clicked_through_at")
        .bind(application_id).bind(hash_token(&input.access_token)).fetch_optional(&state.db).await?;
    let Some(click_row) = click_row else { return Err(AppError::Unauthorized); };
    let clicked_through_at: chrono::DateTime<Utc> = click_row.try_get("clicked_through_at").map_err(|_| AppError::Internal)?;
    sqlx::query("INSERT INTO audit_logs(action,entity_type,entity_id,metadata) VALUES ('application.guest_click_through','application',$1,'{}'::jsonb)")
        .bind(application_id.to_string()).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"application_id":application_id,"official_url":url,"clicked_through_at":clicked_through_at}})))
}

#[utoipa::path(post, path = "/api/v1/auth/claim-guest-applications", tag = "Applications", summary = "Link eligible guest applications to the verified account", security(("bearerAuth" = [])), responses((status = 200, description = "Eligible guest applications linked")))]
pub async fn claim_guest_applications(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    let verified: bool = sqlx::query_scalar("SELECT email_verified_at IS NOT NULL FROM users WHERE id=$1 AND deleted_at IS NULL")
        .bind(user.user_id).fetch_one(&state.db).await?;
    if !verified { return Err(AppError::Validation("Verify your email before linking guest applications".to_string())); }
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE applications guest SET status='deleted',email='deleted+'||guest.id::text||'@deleted.invalid',email_normalized='deleted+'||guest.id::text||'@deleted.invalid',registration_snapshot=jsonb_build_object('school_name',guest.registration_snapshot->>'school_name','course',guest.registration_snapshot->>'course','level',guest.registration_snapshot->>'level','age_range',guest.registration_snapshot->>'age_range'),guest_access_token_hash=NULL,updated_at=now() WHERE guest.user_id IS NULL AND guest.email_normalized=(SELECT email_normalized FROM users WHERE id=$1) AND guest.status='active' AND EXISTS (SELECT 1 FROM applications own WHERE own.user_id=$1 AND own.opportunity_id=guest.opportunity_id AND own.status <> 'deleted')")
        .bind(user.user_id).execute(&mut *tx).await?;
    let result = sqlx::query("UPDATE applications a SET user_id=$1,guest_access_token_hash=NULL,stage=CASE WHEN a.stage='registered' AND EXISTS(SELECT 1 FROM event_checkins c JOIN events e ON e.id=c.event_id JOIN program_opportunities po ON po.program_id=e.program_id WHERE c.user_id=$1 AND po.opportunity_id=a.opportunity_id) THEN 'guided' ELSE a.stage END,updated_at=now() WHERE a.id IN (SELECT guest.id FROM applications guest WHERE guest.user_id IS NULL AND guest.email_normalized=(SELECT email_normalized FROM users WHERE id=$1) AND guest.status='active' AND NOT EXISTS (SELECT 1 FROM applications own WHERE own.user_id=$1 AND own.opportunity_id=guest.opportunity_id AND own.status <> 'deleted'))")
        .bind(user.user_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE consents SET user_id=$1,email_normalized=NULL WHERE user_id IS NULL AND email_normalized=(SELECT email_normalized FROM users WHERE id=$1)")
        .bind(user.user_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'guest_applications.linked','user',$1,$2)")
        .bind(user.user_id).bind(json!({"linked_count":result.rows_affected()})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"success","data":{"linked_count":result.rows_affected()}})))
}

async fn fetch_open_opportunity(state: &AppState, id: Uuid) -> Result<(String, String), AppError> {
    let row = sqlx::query("SELECT title,official_url FROM opportunities WHERE id=$1 AND status='published' AND (application_deadline IS NULL OR application_deadline>now())")
        .bind(id).fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    Ok((row.try_get("title").map_err(|_| AppError::Internal)?, row.try_get("official_url").map_err(|_| AppError::Internal)?))
}
fn normalize_email(email: &str) -> Result<String, AppError> {
    let normalized = email.trim().to_lowercase();
    if normalized.len() > 254 || normalized.len() < 5 || normalized.matches('@').count() != 1 || normalized.split('@').any(|part| part.is_empty()) || normalized.chars().any(char::is_whitespace) {
        return Err(AppError::Validation("Enter a valid email address".to_string()));
    }
    Ok(normalized)
}
fn map_conflict(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_error) = &error { if db_error.code().as_deref() == Some("23505") { return AppError::Conflict; } }
    AppError::Database(error)
}

#[utoipa::path(get, path = "/api/v1/applications/me", tag = "Applications", summary = "List the current user's applications", security(("bearerAuth" = [])), responses((status = 200, description = "Applications returned")))]
pub async fn list_mine(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let page = query.get("page").and_then(|v| v.parse::<i64>().ok()).unwrap_or(1).max(1);
    let page_size = query.get("page_size").and_then(|v| v.parse::<i64>().ok()).unwrap_or(20).clamp(1, 50);
    let offset = (page - 1) * page_size;
    let rows = sqlx::query("SELECT a.id,a.opportunity_id,o.title,o.slug,a.stage,a.status,a.registered_at,a.clicked_through_at,(SELECT count(*) FROM proofs p WHERE p.application_id=a.id) AS proof_count FROM applications a JOIN opportunities o ON o.id=a.opportunity_id WHERE a.user_id=$1 AND a.status='active' ORDER BY a.registered_at DESC LIMIT $2 OFFSET $3")
        .bind(user.user_id).bind(page_size).bind(offset).fetch_all(&state.db).await?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM applications WHERE user_id=$1 AND status='active'")
        .bind(user.user_id).fetch_one(&state.db).await?;
    let items = rows.into_iter().map(|row| json!({
        "id":row.try_get::<Uuid,_>("id").ok(),"opportunity_id":row.try_get::<Uuid,_>("opportunity_id").ok(),
        "opportunity_title":row.try_get::<String,_>("title").ok(),"opportunity_slug":row.try_get::<String,_>("slug").ok(),
        "stage":row.try_get::<String,_>("stage").ok(),"status":row.try_get::<String,_>("status").ok(),
        "registered_at":row.try_get::<chrono::DateTime<Utc>,_>("registered_at").ok(),"clicked_through_at":row.try_get::<Option<chrono::DateTime<Utc>>,_>("clicked_through_at").ok().flatten(),
        "proof_count":row.try_get::<i64,_>("proof_count").unwrap_or(0)
    })).collect::<Vec<_>>();
    Ok(Json(json!({"status":"success","data":{"items":items,"page":page,"page_size":page_size,"total":total}})))
}

#[utoipa::path(get, path = "/api/v1/applications/{application_id}", tag = "Applications", summary = "Get an application and its proof status", params(("application_id" = Uuid, Path)), security(("bearerAuth" = [])), responses((status = 200, description = "Application details returned")))]
pub async fn get_one(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(application_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query("SELECT a.id,a.user_id,a.opportunity_id,o.title,o.slug,a.stage,a.status,a.registration_snapshot,a.registered_at,a.clicked_through_at FROM applications a JOIN opportunities o ON o.id=a.opportunity_id WHERE a.id=$1 AND a.status='active'")
        .bind(application_id).fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    let owner: Option<Uuid> = row.try_get("user_id").map_err(|_| AppError::Internal)?;
    if owner != Some(user.user_id) {
        rbac::require_any_role(&state, &user, &["verifier", "program_manager", "admin"]).await?;
    }
    let proofs = sqlx::query("SELECT id,kind,original_filename,mime_type,size_bytes,status,reviewer_note,reviewed_at,created_at FROM proofs WHERE application_id=$1 ORDER BY created_at DESC")
        .bind(application_id).fetch_all(&state.db).await?;
    let proof_data = proofs.into_iter().map(|p| json!({
        "id":p.try_get::<Uuid,_>("id").ok(),"kind":p.try_get::<String,_>("kind").ok(),"filename":p.try_get::<String,_>("original_filename").ok(),
        "mime_type":p.try_get::<String,_>("mime_type").ok(),"size_bytes":p.try_get::<i64,_>("size_bytes").ok(),"status":p.try_get::<String,_>("status").ok(),
        "reviewer_note":p.try_get::<Option<String>,_>("reviewer_note").ok().flatten(),"reviewed_at":p.try_get::<Option<chrono::DateTime<Utc>>,_>("reviewed_at").ok().flatten(),
        "created_at":p.try_get::<chrono::DateTime<Utc>,_>("created_at").ok()
    })).collect::<Vec<_>>();
    Ok(Json(json!({"status":"success","data":{
        "id":row.try_get::<Uuid,_>("id").map_err(|_| AppError::Internal)?,
        "opportunity_id":row.try_get::<Uuid,_>("opportunity_id").map_err(|_| AppError::Internal)?,
        "opportunity_title":row.try_get::<String,_>("title").map_err(|_| AppError::Internal)?,
        "opportunity_slug":row.try_get::<String,_>("slug").map_err(|_| AppError::Internal)?,
        "stage":row.try_get::<String,_>("stage").map_err(|_| AppError::Internal)?,
        "status":row.try_get::<String,_>("status").map_err(|_| AppError::Internal)?,
        "registration_snapshot":row.try_get::<serde_json::Value,_>("registration_snapshot").map_err(|_| AppError::Internal)?,
        "registered_at":row.try_get::<chrono::DateTime<Utc>,_>("registered_at").map_err(|_| AppError::Internal)?,
        "clicked_through_at":row.try_get::<Option<chrono::DateTime<Utc>>,_>("clicked_through_at").map_err(|_| AppError::Internal)?,
        "proofs":proof_data
    }})))
}
