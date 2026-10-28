use crate::{
    error::AppError,
    middleware::CurrentUser,
    rbac,
    security::{hash_password, hash_token, issue_access_token, new_opaque_token, new_refresh_token, refresh_expiry, session_id_from_refresh, verify_password},
    state::AppState,
};
use axum::{extract::{Path, State}, http::HeaderMap, Extension, Json};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use subtle::ConstantTimeEq;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub full_name: String,
    pub consent_accepted: bool,
    pub consent_version: String,
    pub whatsapp_number: Option<String>,
    pub school_name: Option<String>,
    pub state: Option<String>,
    pub faculty: Option<String>,
    pub department: Option<String>,
    pub course: Option<String>,
    pub level: Option<String>,
    pub age_range: Option<String>,
    pub matriculation_number: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest { pub email: String, pub password: String }
#[derive(Deserialize, ToSchema)]
pub struct RefreshRequest { pub refresh_token: String }
#[derive(Deserialize, ToSchema)]
pub struct VerifyEmailRequest { pub token: String }
#[derive(Deserialize, ToSchema)]
pub struct PasswordResetRequest { pub email: String }
#[derive(Deserialize, ToSchema)]
pub struct ResetPasswordRequest { pub token: String, pub new_password: String }
#[derive(Deserialize, ToSchema)]
pub struct AssignRoleRequest { pub role_code: String }


#[utoipa::path(post, path = "/api/v1/auth/register", tag = "Authentication", summary = "Register a student account", request_body = RegisterRequest, responses((status = 200, description = "Account created")))]
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = normalize_email(&input.email)?;
    let full_name = input.full_name.trim().to_string();
    if full_name.len() < 2 || full_name.len() > 160 { return Err(AppError::Validation("Full name must be 2–160 characters".to_string())); }
    if !input.consent_accepted { return Err(AppError::Validation("Acceptance of the current privacy notice and terms is required to create an account".to_string())); }
    let consent_version = validate_consent_version(&input.consent_version)?;
    validate_age_range(input.age_range.as_deref())?;
    let password_hash = hash_password(&input.password)?;

    let mut tx = state.db.begin().await?;
    let consent_rows = sqlx::query("SELECT consent_type, wording_snapshot FROM consent_documents WHERE version=$1 AND is_current=true FOR SHARE")
        .bind(&consent_version).fetch_all(&mut *tx).await?;
    let privacy_wording = consent_rows.iter()
        .find(|row| row.try_get::<String, _>("consent_type").ok().as_deref() == Some("privacy_notice"))
        .and_then(|row| row.try_get::<String, _>("wording_snapshot").ok())
        .ok_or(AppError::Conflict)?;
    let terms_wording = consent_rows.iter()
        .find(|row| row.try_get::<String, _>("consent_type").ok().as_deref() == Some("terms"))
        .and_then(|row| row.try_get::<String, _>("wording_snapshot").ok())
        .ok_or(AppError::Conflict)?;
    let user_row = sqlx::query(
        "INSERT INTO users(email, email_normalized, password_hash, full_name) VALUES ($1, $2, $3, $4) RETURNING id, email, auth_version"
    )
    .bind(input.email.trim())
    .bind(&email)
    .bind(password_hash)
    .bind(&full_name)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_unique_conflict)?;
    let user_id: Uuid = user_row.try_get("id").map_err(|_| AppError::Internal)?;
    let email_returned: String = user_row.try_get("email").map_err(|_| AppError::Internal)?;
    let auth_version: i64 = user_row.try_get("auth_version").map_err(|_| AppError::Internal)?;

    sqlx::query("INSERT INTO user_roles(user_id, role_code) VALUES ($1, 'student')")
        .bind(user_id).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO student_profiles(user_id, whatsapp_number, school_name, state, faculty, department, course, level, age_range, matriculation_number) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
    )
    .bind(user_id)
    .bind(clean_optional(input.whatsapp_number))
    .bind(clean_optional(input.school_name))
    .bind(clean_optional(input.state))
    .bind(clean_optional(input.faculty))
    .bind(clean_optional(input.department))
    .bind(clean_optional(input.course))
    .bind(clean_optional(input.level))
    .bind(input.age_range)
    .bind(clean_optional(input.matriculation_number))
    .execute(&mut *tx).await?;

    let client_meta = request_meta(&headers);
    sqlx::query("INSERT INTO consents(user_id,consent_type,wording_version,wording_snapshot,accepted,ip_address,user_agent) VALUES ($1,'privacy_notice',$2,$3,true,$4::inet,$5)")
        .bind(user_id).bind(&consent_version).bind(&privacy_wording).bind(client_meta.0.as_deref()).bind(client_meta.1.as_deref()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO consents(user_id,consent_type,wording_version,wording_snapshot,accepted,ip_address,user_agent) VALUES ($1,'terms',$2,$3,true,$4::inet,$5)")
        .bind(user_id).bind(&consent_version).bind(&terms_wording).bind(client_meta.0.as_deref()).bind(client_meta.1.as_deref()).execute(&mut *tx).await?;

    let verification_token = new_opaque_token();
    sqlx::query("INSERT INTO email_verification_tokens(user_id, token_hash, expires_at) VALUES ($1,$2,$3)")
        .bind(user_id).bind(hash_token(&verification_token)).bind(Utc::now() + Duration::hours(24))
        .execute(&mut *tx).await?;
    sqlx::query("INSERT INTO email_outbox(recipient, template, payload) VALUES ($1,'verify_email',$2)")
        .bind(&email_returned)
        .bind(json!({"token": verification_token, "user_id": user_id, "purpose": "verify_email"}))
        .execute(&mut *tx).await?;
    tx.commit().await?;

    let (access_token, refresh_token) = create_session(&state, user_id, auth_version, &headers).await?;
    Ok(Json(json!({
        "status": "success",
        "message": "Account created. Verify your email to link any guest applications.",
        "data": {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": state.config.access_token_ttl_seconds.clamp(60, 3600),
            "refresh_token": refresh_token,
            "user": { "id": user_id, "email": email_returned, "full_name": full_name, "email_verified": false, "roles": ["student"] }
        }
    })))
}

#[utoipa::path(post, path = "/api/v1/auth/login", tag = "Authentication", summary = "Sign in and create a session", request_body = LoginRequest, responses((status = 200, description = "Access and refresh tokens returned")))]
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = normalize_email(&input.email)?;
    if input.password.len() > 128 { return Err(AppError::Unauthorized); }
    let row = sqlx::query("SELECT id, email, password_hash, full_name, auth_version, status, email_verified_at FROM users WHERE email_normalized = $1 AND deleted_at IS NULL")
        .bind(email)
        .fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::Unauthorized); };
    let encoded: String = row.try_get("password_hash").map_err(|_| AppError::Internal)?;
    if !verify_password(&input.password, &encoded) { return Err(AppError::Unauthorized); }
    let status: String = row.try_get("status").map_err(|_| AppError::Internal)?;
    if status != "active" { return Err(AppError::Unauthorized); }
    let user_id: Uuid = row.try_get("id").map_err(|_| AppError::Internal)?;
    let email: String = row.try_get("email").map_err(|_| AppError::Internal)?;
    let full_name: String = row.try_get("full_name").map_err(|_| AppError::Internal)?;
    let auth_version: i64 = row.try_get("auth_version").map_err(|_| AppError::Internal)?;
    let verified: Option<chrono::DateTime<Utc>> = row.try_get("email_verified_at").map_err(|_| AppError::Internal)?;
    let roles = rbac::roles_for(&state, user_id).await?;
    let (access_token, refresh_token) = create_session(&state, user_id, auth_version, &headers).await?;
    Ok(Json(json!({
        "status":"success", "data": {
            "access_token": access_token,
            "token_type":"Bearer",
            "expires_in": state.config.access_token_ttl_seconds.clamp(60, 3600),
            "refresh_token": refresh_token,
            "user": {"id": user_id, "email": email, "full_name": full_name, "email_verified": verified.is_some(), "roles": roles}
        }
    })))
}

#[utoipa::path(post, path = "/api/v1/auth/refresh", tag = "Authentication", summary = "Rotate a refresh token", request_body = RefreshRequest, responses((status = 200, description = "Tokens rotated")))]
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<RefreshRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let session_id = session_id_from_refresh(&input.refresh_token)?;
    let provided_hash = hash_token(&input.refresh_token);
    let mut tx = state.db.begin().await?;
    let row = sqlx::query("SELECT user_id, refresh_token_hash, expires_at, revoked_at FROM user_sessions WHERE id = $1 FOR UPDATE")
        .bind(session_id).fetch_optional(&mut *tx).await?;
    let Some(row) = row else { return Err(AppError::Unauthorized); };
    let stored_hash: Vec<u8> = row.try_get("refresh_token_hash").map_err(|_| AppError::Internal)?;
    let expires_at: chrono::DateTime<Utc> = row.try_get("expires_at").map_err(|_| AppError::Internal)?;
    let revoked_at: Option<chrono::DateTime<Utc>> = row.try_get("revoked_at").map_err(|_| AppError::Internal)?;
    if revoked_at.is_some() || expires_at <= Utc::now() { return Err(AppError::Unauthorized); }
    if stored_hash.as_slice().ct_eq(provided_hash.as_slice()).unwrap_u8() != 1 {
        sqlx::query("UPDATE user_sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
            .bind(session_id).execute(&mut *tx).await?;
        tx.commit().await?;
        return Err(AppError::Unauthorized);
    }
    let user_id: Uuid = row.try_get("user_id").map_err(|_| AppError::Internal)?;
    let user_row = sqlx::query("SELECT auth_version, status FROM users WHERE id = $1 AND deleted_at IS NULL")
        .bind(user_id).fetch_optional(&mut *tx).await?;
    let Some(user_row) = user_row else { return Err(AppError::Unauthorized); };
    let auth_version: i64 = user_row.try_get("auth_version").map_err(|_| AppError::Internal)?;
    let status: String = user_row.try_get("status").map_err(|_| AppError::Internal)?;
    if status != "active" { return Err(AppError::Unauthorized); }
    let new_refresh = new_refresh_token(session_id);
    let new_hash = hash_token(&new_refresh);
    sqlx::query("UPDATE user_sessions SET refresh_token_hash=$2, last_refreshed_at=now(), expires_at=$3, ip_address=$4::inet, user_agent=$5 WHERE id=$1")
        .bind(session_id).bind(new_hash).bind(refresh_expiry(&state.config))
        .bind(request_meta(&headers).0.as_deref()).bind(request_meta(&headers).1.as_deref())
        .execute(&mut *tx).await?;
    tx.commit().await?;
    let access = issue_access_token(user_id, session_id, auth_version, &state.config)?;
    Ok(Json(json!({"status":"success","data":{"access_token":access,"token_type":"Bearer","expires_in":state.config.access_token_ttl_seconds.clamp(60,3600),"refresh_token":new_refresh}})))
}

#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "Authentication", summary = "Revoke the current session", security(("bearerAuth" = [])), responses((status = 200, description = "Session revoked")))]
pub async fn logout(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    sqlx::query("UPDATE user_sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL")
        .bind(user.session_id).bind(user.user_id).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","message":"Session revoked"})))
}

#[utoipa::path(get, path = "/api/v1/auth/me", tag = "Authentication", summary = "Get the current account", security(("bearerAuth" = [])), responses((status = 200, description = "Current account")))]
pub async fn me(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query(
        "SELECT u.id,u.email,u.full_name,u.email_verified_at,u.created_at,p.whatsapp_number,p.school_name,p.state,p.faculty,p.department,p.course,p.level,p.age_range,p.matriculation_number,p.interests FROM users u LEFT JOIN student_profiles p ON p.user_id=u.id WHERE u.id=$1 AND u.deleted_at IS NULL"
    ).bind(user.user_id).fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    let roles = rbac::roles_for(&state, user.user_id).await?;
    Ok(Json(json!({"status":"success","data":{
        "id": row.try_get::<Uuid,_>("id").map_err(|_| AppError::Internal)?,
        "email": row.try_get::<String,_>("email").map_err(|_| AppError::Internal)?,
        "full_name": row.try_get::<String,_>("full_name").map_err(|_| AppError::Internal)?,
        "email_verified": row.try_get::<Option<chrono::DateTime<Utc>>,_>("email_verified_at").map_err(|_| AppError::Internal)?.is_some(),
        "created_at": row.try_get::<chrono::DateTime<Utc>,_>("created_at").map_err(|_| AppError::Internal)?,
        "profile": {
            "whatsapp_number": row.try_get::<Option<String>,_>("whatsapp_number").map_err(|_| AppError::Internal)?,
            "school_name": row.try_get::<Option<String>,_>("school_name").map_err(|_| AppError::Internal)?,
            "state": row.try_get::<Option<String>,_>("state").map_err(|_| AppError::Internal)?,
            "faculty": row.try_get::<Option<String>,_>("faculty").map_err(|_| AppError::Internal)?,
            "department": row.try_get::<Option<String>,_>("department").map_err(|_| AppError::Internal)?,
            "course": row.try_get::<Option<String>,_>("course").map_err(|_| AppError::Internal)?,
            "level": row.try_get::<Option<String>,_>("level").map_err(|_| AppError::Internal)?,
            "age_range": row.try_get::<Option<String>,_>("age_range").map_err(|_| AppError::Internal)?,
            "matriculation_number": row.try_get::<Option<String>,_>("matriculation_number").map_err(|_| AppError::Internal)?,
            "interests": row.try_get::<Vec<String>,_>("interests").map_err(|_| AppError::Internal)?
        }, "roles": roles
    }})))
}

#[utoipa::path(post, path = "/api/v1/auth/verify-email", tag = "Authentication", summary = "Verify an email address", request_body = VerifyEmailRequest, responses((status = 200, description = "Email verified")))]
pub async fn verify_email(
    State(state): State<AppState>,
    Json(input): Json<VerifyEmailRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if input.token.len() < 40 || input.token.len() > 64 { return Err(AppError::BadRequest("Invalid verification token")); }
    let digest = hash_token(&input.token);
    let mut tx = state.db.begin().await?;
    let token_row = sqlx::query("SELECT id,user_id FROM email_verification_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE")
        .bind(digest).fetch_optional(&mut *tx).await?;
    let Some(token_row) = token_row else { return Err(AppError::BadRequest("Verification token is invalid or expired")); };
    let token_id: Uuid = token_row.try_get("id").map_err(|_| AppError::Internal)?;
    let user_id: Uuid = token_row.try_get("user_id").map_err(|_| AppError::Internal)?;
    sqlx::query("UPDATE users SET email_verified_at=COALESCE(email_verified_at,now()),updated_at=now() WHERE id=$1").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE email_verification_tokens SET used_at=now() WHERE id=$1").bind(token_id).execute(&mut *tx).await?;
    // When the account already has an application for an opportunity, anonymise the duplicate guest row
    // instead of letting a uniqueness conflict leave personal data stranded in an unclaimable guest record.
    sqlx::query("UPDATE applications guest SET status='deleted',email='deleted+'||guest.id::text||'@deleted.invalid',email_normalized='deleted+'||guest.id::text||'@deleted.invalid',registration_snapshot=jsonb_build_object('school_name',guest.registration_snapshot->>'school_name','course',guest.registration_snapshot->>'course','level',guest.registration_snapshot->>'level','age_range',guest.registration_snapshot->>'age_range'),guest_access_token_hash=NULL,updated_at=now() WHERE guest.user_id IS NULL AND guest.email_normalized=(SELECT email_normalized FROM users WHERE id=$1) AND guest.status='active' AND EXISTS (SELECT 1 FROM applications own WHERE own.user_id=$1 AND own.opportunity_id=guest.opportunity_id AND own.status <> 'deleted')")
        .bind(user_id).execute(&mut *tx).await?;
    // Guest applications and their consent proofs are linked only after verified email ownership.
    sqlx::query("UPDATE applications a SET user_id=$1,guest_access_token_hash=NULL,stage=CASE WHEN a.stage='registered' AND EXISTS(SELECT 1 FROM event_checkins c JOIN events e ON e.id=c.event_id JOIN program_opportunities po ON po.program_id=e.program_id WHERE c.user_id=$1 AND po.opportunity_id=a.opportunity_id) THEN 'guided' ELSE a.stage END,updated_at=now() WHERE a.id IN (SELECT guest.id FROM applications guest WHERE guest.user_id IS NULL AND guest.email_normalized=(SELECT email_normalized FROM users WHERE id=$1) AND guest.status='active' AND NOT EXISTS (SELECT 1 FROM applications own WHERE own.user_id=$1 AND own.opportunity_id=guest.opportunity_id AND own.status <> 'deleted'))")
        .bind(user_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE consents SET user_id=$1,email_normalized=NULL WHERE user_id IS NULL AND email_normalized=(SELECT email_normalized FROM users WHERE id=$1)")
        .bind(user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"success","message":"Email verified. Eligible guest applications have been linked."})))
}

#[utoipa::path(post, path = "/api/v1/auth/request-password-reset", tag = "Authentication", summary = "Request a password reset email", request_body = PasswordResetRequest, responses((status = 200, description = "Generic response; does not reveal whether the account exists")))]
pub async fn request_password_reset(
    State(state): State<AppState>,
    Json(input): Json<PasswordResetRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Always return the same response to avoid disclosing whether an address has an account.
    if let Ok(email) = normalize_email(&input.email) {
        if let Some(row) = sqlx::query("SELECT id,email FROM users WHERE email_normalized=$1 AND status='active' AND deleted_at IS NULL")
            .bind(email).fetch_optional(&state.db).await? {
            let user_id: Uuid = row.try_get("id").map_err(|_| AppError::Internal)?;
            let recipient: String = row.try_get("email").map_err(|_| AppError::Internal)?;
            let token = new_opaque_token();
            let mut tx = state.db.begin().await?;
            sqlx::query("UPDATE password_reset_tokens SET used_at=now() WHERE user_id=$1 AND used_at IS NULL").bind(user_id).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO password_reset_tokens(user_id,token_hash,expires_at) VALUES ($1,$2,$3)")
                .bind(user_id).bind(hash_token(&token)).bind(Utc::now()+Duration::minutes(20)).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO email_outbox(recipient,template,payload) VALUES ($1,'password_reset',$2)")
                .bind(recipient).bind(json!({"token":token,"user_id":user_id,"purpose":"password_reset"})).execute(&mut *tx).await?;
            tx.commit().await?;
        }
    }
    Ok(Json(json!({"status":"success","message":"If the account exists, password-reset instructions will be sent."})))
}

#[utoipa::path(post, path = "/api/v1/auth/reset-password", tag = "Authentication", summary = "Set a new password with a reset token", request_body = ResetPasswordRequest, responses((status = 200, description = "Password updated")))]
pub async fn reset_password(
    State(state): State<AppState>,
    Json(input): Json<ResetPasswordRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let new_hash = hash_password(&input.new_password)?;
    if input.token.len() < 40 || input.token.len() > 64 { return Err(AppError::BadRequest("Invalid or expired reset token")); }
    let digest = hash_token(&input.token);
    let mut tx = state.db.begin().await?;
    let row = sqlx::query("SELECT id,user_id FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>now() FOR UPDATE")
        .bind(digest).fetch_optional(&mut *tx).await?;
    let Some(row) = row else { return Err(AppError::BadRequest("Invalid or expired reset token")); };
    let token_id: Uuid = row.try_get("id").map_err(|_| AppError::Internal)?;
    let user_id: Uuid = row.try_get("user_id").map_err(|_| AppError::Internal)?;
    sqlx::query("UPDATE users SET password_hash=$2,auth_version=auth_version+1,updated_at=now() WHERE id=$1")
        .bind(user_id).bind(new_hash).execute(&mut *tx).await?;
    sqlx::query("UPDATE user_sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE password_reset_tokens SET used_at=now() WHERE id=$1").bind(token_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"success","message":"Password updated. Please sign in again."})))
}

#[derive(Deserialize, ToSchema)]
pub struct PublishConsentDocumentsRequest {
    pub version: String,
    pub privacy_notice_text: String,
    pub terms_text: String,
}

/// Public endpoint used by web/mobile clients to render the exact consent wording.
#[utoipa::path(get, path = "/api/v1/consent-documents/current", tag = "Consent", summary = "Get the current privacy notice and terms", responses((status = 200, description = "Current consent documents")))]
pub async fn current_consent_documents(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows = sqlx::query("SELECT consent_type,version,wording_snapshot,published_at FROM consent_documents WHERE is_current=true ORDER BY consent_type")
        .fetch_all(&state.db).await?;
    let documents = rows.into_iter().map(|row| json!({
        "type": row.try_get::<String, _>("consent_type").ok(),
        "version": row.try_get::<String, _>("version").ok(),
        "text": row.try_get::<String, _>("wording_snapshot").ok(),
        "published_at": row.try_get::<chrono::DateTime<Utc>, _>("published_at").ok(),
    })).collect::<Vec<_>>();
    Ok(Json(json!({"status":"success","data":{"documents":documents}})))
}

/// Admin publishes immutable, server-owned consent wording. A client may submit only the version.
#[utoipa::path(post, path = "/api/v1/admin/consent-documents", tag = "Consent", summary = "Publish versioned consent wording", request_body = PublishConsentDocumentsRequest, security(("bearerAuth" = [])), responses((status = 200, description = "Consent documents published")))]
pub async fn publish_consent_documents(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Json(input): Json<PublishConsentDocumentsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["admin"]).await?;
    let version = validate_consent_version(&input.version)?;
    let privacy = input.privacy_notice_text.trim();
    let terms = input.terms_text.trim();
    if !(20..=50_000).contains(&privacy.chars().count()) || !(20..=50_000).contains(&terms.chars().count()) {
        return Err(AppError::Validation("Privacy notice and terms must each contain 20–50,000 characters".to_string()));
    }

    let mut tx = state.db.begin().await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM consent_documents WHERE version=$1 AND consent_type IN ('privacy_notice','terms'))")
        .bind(&version).fetch_one(&mut *tx).await?;
    if exists { return Err(AppError::Conflict); }

    sqlx::query("UPDATE consent_documents SET is_current=false WHERE is_current=true")
        .execute(&mut *tx).await?;
    sqlx::query("INSERT INTO consent_documents(consent_type,version,wording_snapshot,is_current,published_by) VALUES ('privacy_notice',$1,$2,true,$3),('terms',$1,$4,true,$3)")
        .bind(&version).bind(privacy).bind(actor.user_id).bind(terms).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'consent.documents_published','consent_documents',$2,$3)")
        .bind(actor.user_id).bind(&version).bind(json!({"document_types":["privacy_notice","terms"]})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"success","message":"Consent documents published","data":{"version":version,"types":["privacy_notice","terms"]}})))
}

fn validate_consent_version(value: &str) -> Result<String, AppError> {
    let version = value.trim();
    if version.is_empty() || version.len() > 100 || !version.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
        return Err(AppError::Validation("Consent version must contain only letters, numbers, dots, dashes or underscores (max 100 characters)".to_string()));
    }
    Ok(version.to_string())
}

#[utoipa::path(post, path = "/api/v1/admin/users/{user_id}/roles", tag = "Administration", summary = "Assign a role to a user", params(("user_id" = Uuid, Path)), request_body = AssignRoleRequest, security(("bearerAuth" = [])), responses((status = 200, description = "Role assigned")))]
pub async fn assign_role(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path(target_user): Path<Uuid>,
    Json(input): Json<AssignRoleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["admin"]).await?;
    const ALLOWED: &[&str] = &["student", "verifier", "program_manager", "admin", "partner_viewer", "mentor"];
    if !ALLOWED.contains(&input.role_code.as_str()) { return Err(AppError::Validation("Unknown role".to_string())); }
    let mut tx = state.db.begin().await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND deleted_at IS NULL)")
        .bind(target_user).fetch_one(&mut *tx).await?;
    if !exists { return Err(AppError::NotFound); }
    sqlx::query("INSERT INTO user_roles(user_id,role_code,assigned_by) VALUES ($1,$2,$3) ON CONFLICT(user_id,role_code) DO NOTHING")
        .bind(target_user).bind(&input.role_code).bind(actor.user_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'role.assigned','user',$2,$3)")
        .bind(actor.user_id).bind(target_user.to_string()).bind(json!({"role_code":input.role_code})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"success","message":"Role assigned"})))
}

async fn create_session(state: &AppState, user_id: Uuid, auth_version: i64, headers: &HeaderMap) -> Result<(String, String), AppError> {
    let session_id = Uuid::new_v4();
    let refresh_token = new_refresh_token(session_id);
    let meta = request_meta(headers);
    sqlx::query("INSERT INTO user_sessions(id,user_id,refresh_token_hash,expires_at,ip_address,user_agent) VALUES ($1,$2,$3,$4,$5::inet,$6)")
        .bind(session_id).bind(user_id).bind(hash_token(&refresh_token)).bind(refresh_expiry(&state.config))
        .bind(meta.0.as_deref()).bind(meta.1.as_deref()).execute(&state.db).await?;
    let access = issue_access_token(user_id, session_id, auth_version, &state.config)?;
    Ok((access, refresh_token))
}

fn normalize_email(email: &str) -> Result<String, AppError> {
    let normalized = email.trim().to_lowercase();
    if normalized.len() > 254 || normalized.len() < 5 || normalized.matches('@').count() != 1 || normalized.split('@').any(|p| p.is_empty()) || normalized.chars().any(char::is_whitespace) {
        return Err(AppError::Validation("Enter a valid email address".to_string()));
    }
    Ok(normalized)
}

fn validate_age_range(value: Option<&str>) -> Result<(), AppError> {
    if let Some(v) = value {
        if !["under_18", "18_20", "21_24", "25_29", "30_plus", "prefer_not_to_say"].contains(&v) {
            return Err(AppError::Validation("Invalid age range".to_string()));
        }
    }
    Ok(())
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|v| { let value = v.trim().to_string(); if value.is_empty() { None } else { Some(value) } })
}

fn request_meta(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let agent = headers.get(axum::http::header::USER_AGENT).and_then(|h| h.to_str().ok()).map(|s| s.chars().take(512).collect::<String>());
    // Never trust a client-supplied forwarding header by default. Ingress can inject trusted client IP metadata later.
    (None, agent)
}

fn map_unique_conflict(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.code().as_deref() == Some("23505") { return AppError::Conflict; }
    }
    AppError::Database(error)
}

#[derive(Deserialize, ToSchema)]
pub struct ProfileUpdate {
    pub full_name: Option<String>,
    pub whatsapp_number: Option<String>,
    pub school_name: Option<String>,
    pub state: Option<String>,
    pub faculty: Option<String>,
    pub department: Option<String>,
    pub course: Option<String>,
    pub level: Option<String>,
    pub age_range: Option<String>,
    pub matriculation_number: Option<String>,
    pub interests: Option<Vec<String>>,
}
#[derive(Deserialize, ToSchema)]
pub struct DeleteAccountRequest { pub password: String }

#[utoipa::path(patch, path = "/api/v1/auth/me", tag = "Authentication", summary = "Update the current profile", request_body = ProfileUpdate, security(("bearerAuth" = [])), responses((status = 200, description = "Profile updated")))]
pub async fn update_me(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(input): Json<ProfileUpdate>,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(name) = input.full_name.as_deref() {
        if name.trim().len() < 2 || name.trim().len() > 160 { return Err(AppError::Validation("Full name must be 2–160 characters".to_string())); }
    }
    validate_age_range(input.age_range.as_deref())?;
    if input.interests.as_ref().is_some_and(|values| values.len() > 30 || values.iter().any(|v| v.trim().len() > 80)) {
        return Err(AppError::Validation("Up to 30 interests are allowed, each up to 80 characters".to_string()));
    }
    let mut tx = state.db.begin().await?;
    if let Some(name) = input.full_name.as_deref() {
        sqlx::query("UPDATE users SET full_name=$2,updated_at=now() WHERE id=$1 AND deleted_at IS NULL")
            .bind(user.user_id).bind(name.trim()).execute(&mut *tx).await?;
    }
    let updated_interests = input.interests.map(|values| values.into_iter().map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).collect::<Vec<_>>());
    let insert_interests = updated_interests.clone().unwrap_or_default();
    sqlx::query(
        "INSERT INTO student_profiles(user_id,whatsapp_number,school_name,state,faculty,department,course,level,age_range,matriculation_number,interests,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now()) ON CONFLICT(user_id) DO UPDATE SET whatsapp_number=COALESCE(EXCLUDED.whatsapp_number,student_profiles.whatsapp_number),school_name=COALESCE(EXCLUDED.school_name,student_profiles.school_name),state=COALESCE(EXCLUDED.state,student_profiles.state),faculty=COALESCE(EXCLUDED.faculty,student_profiles.faculty),department=COALESCE(EXCLUDED.department,student_profiles.department),course=COALESCE(EXCLUDED.course,student_profiles.course),level=COALESCE(EXCLUDED.level,student_profiles.level),age_range=COALESCE(EXCLUDED.age_range,student_profiles.age_range),matriculation_number=COALESCE(EXCLUDED.matriculation_number,student_profiles.matriculation_number),interests=COALESCE($12,student_profiles.interests),updated_at=now()"
    )
    .bind(user.user_id).bind(clean_optional(input.whatsapp_number)).bind(clean_optional(input.school_name)).bind(clean_optional(input.state))
    .bind(clean_optional(input.faculty)).bind(clean_optional(input.department)).bind(clean_optional(input.course)).bind(clean_optional(input.level))
    .bind(input.age_range).bind(clean_optional(input.matriculation_number)).bind(insert_interests)
    .bind(updated_interests)
    .execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'profile.updated','user',$1,$2)")
        .bind(user.user_id).bind(json!({"profile_updated":true})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"success","message":"Profile updated"})))
}

#[utoipa::path(get, path = "/api/v1/auth/me/export", tag = "Authentication", summary = "Export the current user's personal data", security(("bearerAuth" = [])), responses((status = 200, description = "Personal data export")))]
pub async fn export_me(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, AppError> {
    let profile = sqlx::query("SELECT u.email,u.full_name,u.created_at,u.email_verified_at,p.whatsapp_number,p.school_name,p.state,p.faculty,p.department,p.course,p.level,p.age_range,p.matriculation_number,p.interests FROM users u LEFT JOIN student_profiles p ON p.user_id=u.id WHERE u.id=$1 AND u.deleted_at IS NULL")
        .bind(user.user_id).fetch_optional(&state.db).await?;
    let Some(profile) = profile else { return Err(AppError::NotFound); };
    let apps = sqlx::query("SELECT a.id,a.opportunity_id,o.title,a.stage,a.status,a.registration_snapshot,a.registered_at,a.clicked_through_at FROM applications a JOIN opportunities o ON o.id=a.opportunity_id WHERE a.user_id=$1 ORDER BY a.registered_at DESC")
        .bind(user.user_id).fetch_all(&state.db).await?;
    let app_data = apps.into_iter().map(|row| json!({
        "id":row.try_get::<Uuid,_>("id").ok(),"opportunity_id":row.try_get::<Uuid,_>("opportunity_id").ok(),
        "opportunity_title":row.try_get::<String,_>("title").ok(),"stage":row.try_get::<String,_>("stage").ok(),
        "status":row.try_get::<String,_>("status").ok(),"registration_snapshot":row.try_get::<serde_json::Value,_>("registration_snapshot").ok(),
        "registered_at":row.try_get::<chrono::DateTime<Utc>,_>("registered_at").ok(),"clicked_through_at":row.try_get::<Option<chrono::DateTime<Utc>>,_>("clicked_through_at").ok().flatten()
    })).collect::<Vec<_>>();
    let checkins = sqlx::query("SELECT c.event_id,e.name,e.starts_at,c.checked_in_at,c.method FROM event_checkins c JOIN events e ON e.id=c.event_id WHERE c.user_id=$1 ORDER BY c.checked_in_at DESC")
        .bind(user.user_id).fetch_all(&state.db).await?;
    let checkin_data = checkins.into_iter().map(|row| json!({
        "event_id":row.try_get::<Uuid,_>("event_id").ok(),"event_name":row.try_get::<String,_>("name").ok(),
        "starts_at":row.try_get::<chrono::DateTime<Utc>,_>("starts_at").ok(),"checked_in_at":row.try_get::<chrono::DateTime<Utc>,_>("checked_in_at").ok(),"method":row.try_get::<String,_>("method").ok()
    })).collect::<Vec<_>>();
    let consents = sqlx::query("SELECT consent_type,wording_version,wording_snapshot,accepted,accepted_at FROM consents WHERE user_id=$1 ORDER BY accepted_at")
        .bind(user.user_id).fetch_all(&state.db).await?;
    let consent_data = consents.into_iter().map(|row| json!({
        "consent_type":row.try_get::<String,_>("consent_type").ok(),"wording_version":row.try_get::<String,_>("wording_version").ok(),
        "wording_snapshot":row.try_get::<String,_>("wording_snapshot").ok(),"accepted":row.try_get::<bool,_>("accepted").ok(),"accepted_at":row.try_get::<chrono::DateTime<Utc>,_>("accepted_at").ok()
    })).collect::<Vec<_>>();
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'personal_data.exported','user',$1,'{}'::jsonb)")
        .bind(user.user_id).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{
        "exported_at":Utc::now(),
        "account":{"email":profile.try_get::<String,_>("email").map_err(|_| AppError::Internal)?,"full_name":profile.try_get::<String,_>("full_name").map_err(|_| AppError::Internal)?,"created_at":profile.try_get::<chrono::DateTime<Utc>,_>("created_at").map_err(|_| AppError::Internal)?,"email_verified":profile.try_get::<Option<chrono::DateTime<Utc>>,_>("email_verified_at").map_err(|_| AppError::Internal)?.is_some()},
        "profile":{"whatsapp_number":profile.try_get::<Option<String>,_>("whatsapp_number").map_err(|_| AppError::Internal)?,"school_name":profile.try_get::<Option<String>,_>("school_name").map_err(|_| AppError::Internal)?,"state":profile.try_get::<Option<String>,_>("state").map_err(|_| AppError::Internal)?,"faculty":profile.try_get::<Option<String>,_>("faculty").map_err(|_| AppError::Internal)?,"department":profile.try_get::<Option<String>,_>("department").map_err(|_| AppError::Internal)?,"course":profile.try_get::<Option<String>,_>("course").map_err(|_| AppError::Internal)?,"level":profile.try_get::<Option<String>,_>("level").map_err(|_| AppError::Internal)?,"age_range":profile.try_get::<Option<String>,_>("age_range").map_err(|_| AppError::Internal)?,"matriculation_number":profile.try_get::<Option<String>,_>("matriculation_number").map_err(|_| AppError::Internal)?,"interests":profile.try_get::<Vec<String>,_>("interests").map_err(|_| AppError::Internal)?},
        "applications":app_data,"event_checkins":checkin_data,"consents":consent_data
    }})))
}

#[utoipa::path(delete, path = "/api/v1/auth/me", tag = "Authentication", summary = "Request account deletion", request_body = DeleteAccountRequest, security(("bearerAuth" = [])), responses((status = 200, description = "Account deletion processed")))]
pub async fn delete_me(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(input): Json<DeleteAccountRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if input.password.len() > 128 { return Err(AppError::Unauthorized); }
    let row = sqlx::query("SELECT password_hash FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL")
        .bind(user.user_id).fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    let password_hash: String = row.try_get("password_hash").map_err(|_| AppError::Internal)?;
    if !verify_password(&input.password, &password_hash) { return Err(AppError::Unauthorized); }
    let current_roles = rbac::roles_for(&state, user.user_id).await?;
    if current_roles.iter().any(|role| role == "admin") {
        return Err(AppError::Validation("Admin accounts must be deprovisioned by another administrator".to_string()));
    }
    anonymise_user_data(&state, user.user_id, user.user_id, "personal_data.deleted", None).await?;
    Ok(Json(json!({"status":"success","message":"Personal account details have been anonymised and active sessions revoked. Aggregated program records are retained."})))
}

#[derive(Deserialize, ToSchema)]
pub struct AdminAnonymiseRequest { pub reason: String }

#[utoipa::path(post, path = "/api/v1/admin/users/{user_id}/anonymise", tag = "Administration", summary = "Anonymise a user account", params(("user_id" = Uuid, Path)), request_body = AdminAnonymiseRequest, security(("bearerAuth" = [])), responses((status = 200, description = "User anonymised")))]
pub async fn admin_anonymise_user(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path(target_user_id): Path<Uuid>,
    Json(input): Json<AdminAnonymiseRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["admin"]).await?;
    let reason = input.reason.trim();
    if reason.len() < 5 || reason.len() > 1000 {
        return Err(AppError::Validation("A reason of 5–1000 characters is required".to_string()));
    }
    if target_user_id == actor.user_id {
        return Err(AppError::Validation("Use the self-service account deletion workflow for your own account".to_string()));
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL)")
        .bind(target_user_id).fetch_one(&state.db).await?;
    if !exists { return Err(AppError::NotFound); }
    let target_roles = rbac::roles_for(&state, target_user_id).await?;
    if target_roles.iter().any(|role| role == "admin") {
        let admin_count: i64 = sqlx::query_scalar("SELECT count(*) FROM user_roles ur JOIN users u ON u.id=ur.user_id WHERE ur.role_code='admin' AND u.status='active' AND u.deleted_at IS NULL")
            .fetch_one(&state.db).await?;
        if admin_count <= 1 { return Err(AppError::Conflict); }
    }
    anonymise_user_data(&state, target_user_id, actor.user_id, "admin.personal_data.deleted", Some(reason)).await?;
    Ok(Json(json!({"status":"success","message":"The user's personal account data has been anonymised.","data":{"user_id":target_user_id}})))
}

async fn anonymise_user_data(
    state: &AppState,
    target_user_id: Uuid,
    actor_user_id: Uuid,
    audit_action: &str,
    reason: Option<&str>,
) -> Result<(), AppError> {
    let target = sqlx::query("SELECT email,email_normalized FROM users WHERE id=$1 AND deleted_at IS NULL")
        .bind(target_user_id).fetch_optional(&state.db).await?;
    let Some(target) = target else { return Err(AppError::NotFound); };
    let original_email: String = target.try_get("email").map_err(|_| AppError::Internal)?;
    let original_normalized: String = target.try_get("email_normalized").map_err(|_| AppError::Internal)?;

    // Guest applications under the same email are included so deleting an account does not leave an unlinked copy of the person's data.
    let proof_rows = sqlx::query("SELECT p.object_key FROM proofs p JOIN applications a ON a.id=p.application_id WHERE a.user_id=$1 OR (a.user_id IS NULL AND a.email_normalized=$2)")
        .bind(target_user_id).bind(&original_normalized).fetch_all(&state.db).await?;
    let mut removed_proof_count = 0_u64;
    for proof in proof_rows {
        let object_key: String = proof.try_get("object_key").map_err(|_| AppError::Internal)?;
        crate::proofs::delete_private_file(&state.config.private_storage_dir, &object_key).await?;
        removed_proof_count += 1;
    }

    let mut tx = state.db.begin().await?;
    let anonymised_application_ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE applications SET user_id=NULL,email='deleted+'||id::text||'@deleted.invalid',email_normalized='deleted+'||id::text||'@deleted.invalid',registration_snapshot=jsonb_build_object('school_name',registration_snapshot->>'school_name','course',registration_snapshot->>'course','level',registration_snapshot->>'level','age_range',registration_snapshot->>'age_range'),guest_access_token_hash=NULL,updated_at=now() WHERE user_id=$1 OR (user_id IS NULL AND email_normalized=$2) RETURNING id"
    ).bind(target_user_id).bind(&original_normalized).fetch_all(&mut *tx).await?;
    sqlx::query("UPDATE event_checkins SET user_id=NULL WHERE user_id=$1").bind(target_user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM activity_days WHERE user_id=$1").bind(target_user_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE consents SET user_id=NULL,email_normalized=NULL,ip_address=NULL,user_agent=NULL,anonymised_at=now() WHERE user_id=$1 OR email_normalized=$2")
        .bind(target_user_id).bind(&original_normalized).execute(&mut *tx).await?;
    sqlx::query("UPDATE proofs SET uploaded_by=NULL,object_key='deleted/'||id::text,original_filename='deleted',sha256=decode(repeat('00',32),'hex'),reviewer_note=NULL,storage_deleted_at=now() WHERE application_id = ANY($1)")
        .bind(&anonymised_application_ids).execute(&mut *tx).await?;
    sqlx::query("UPDATE verification_decisions SET note=NULL WHERE application_id = ANY($1)")
        .bind(&anonymised_application_ids).execute(&mut *tx).await?;
    sqlx::query("UPDATE surveys SET answers='{}'::jsonb WHERE application_id = ANY($1)")
        .bind(&anonymised_application_ids).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id=$1").bind(target_user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id=$1").bind(target_user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM email_verification_tokens WHERE user_id=$1").bind(target_user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM email_outbox WHERE recipient=$1 OR recipient=$2").bind(&original_email).bind(&original_normalized).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM user_roles WHERE user_id=$1").bind(target_user_id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM student_profiles WHERE user_id=$1").bind(target_user_id).execute(&mut *tx).await?;
    let scrubbed_email = format!("deleted+{}@deleted.invalid", target_user_id);
    let replacement_password = hash_password(&new_opaque_token())?;
    sqlx::query("UPDATE users SET email=$2,email_normalized=$2,full_name='Deleted Account',password_hash=$3,status='deleted',email_verified_at=NULL,auth_version=auth_version+1,deleted_at=now(),updated_at=now() WHERE id=$1")
        .bind(target_user_id).bind(scrubbed_email).bind(replacement_password).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,$2,'user',$3,$4)")
        .bind(actor_user_id).bind(audit_action).bind(target_user_id.to_string()).bind(json!({"proof_files_removed":removed_proof_count,"application_rows_anonymised":anonymised_application_ids.len(),"reason":reason})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

#[utoipa::path(get, path = "/api/v1/admin/audit-logs", tag = "Administration", summary = "List audit records", security(("bearerAuth" = [])), responses((status = 200, description = "Audit log entries")))]
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["admin"]).await?;
    let page = query.get("page").and_then(|v| v.parse::<i64>().ok()).unwrap_or(1).max(1);
    let page_size = query.get("page_size").and_then(|v| v.parse::<i64>().ok()).unwrap_or(50).clamp(1, 100);
    let offset = (page - 1) * page_size;
    let action = query.get("action").map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let rows = sqlx::query("SELECT l.id,l.actor_user_id,u.email AS actor_email,l.action,l.entity_type,l.entity_id,l.metadata,l.created_at FROM audit_logs l LEFT JOIN users u ON u.id=l.actor_user_id WHERE ($1::text IS NULL OR l.action=$1) ORDER BY l.created_at DESC LIMIT $2 OFFSET $3")
        .bind(&action).bind(page_size).bind(offset).fetch_all(&state.db).await?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE ($1::text IS NULL OR action=$1)")
        .bind(action).fetch_one(&state.db).await?;
    let items = rows.into_iter().map(|row| json!({
        "id":row.try_get::<i64,_>("id").ok(),"actor_user_id":row.try_get::<Option<Uuid>,_>("actor_user_id").ok().flatten(),
        "actor_email":row.try_get::<Option<String>,_>("actor_email").ok().flatten(),"action":row.try_get::<String,_>("action").ok(),
        "entity_type":row.try_get::<String,_>("entity_type").ok(),"entity_id":row.try_get::<Option<String>,_>("entity_id").ok().flatten(),
        "metadata":row.try_get::<serde_json::Value,_>("metadata").ok(),"created_at":row.try_get::<chrono::DateTime<Utc>,_>("created_at").ok()
    })).collect::<Vec<_>>();
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'audit_logs.viewed','audit_log',NULL,$2)")
        .bind(actor.user_id).bind(json!({"page":page,"page_size":page_size})).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{"items":items,"page":page,"page_size":page_size,"total":total}})))
}

#[utoipa::path(delete, path = "/api/v1/admin/users/{user_id}/roles/{role_code}", tag = "Administration", summary = "Remove a role from a user", params(("user_id" = Uuid, Path), ("role_code" = String, Path)), security(("bearerAuth" = [])), responses((status = 200, description = "Role removed")))]
pub async fn remove_role(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path((target_user_id, role_code)): Path<(Uuid, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["admin"]).await?;
    const ALLOWED: &[&str] = &["student", "verifier", "program_manager", "admin", "partner_viewer", "mentor"];
    if !ALLOWED.contains(&role_code.as_str()) { return Err(AppError::Validation("Unknown role".to_string())); }

    let mut tx = state.db.begin().await?;
    if role_code == "admin" {
        // Serialise admin-removal decisions so two concurrent requests cannot remove the last admins.
        sqlx::query("SELECT pg_advisory_xact_lock(916013700019::bigint)")
            .execute(&mut *tx).await?;
        let admins: i64 = sqlx::query_scalar("SELECT count(*) FROM user_roles ur JOIN users u ON u.id=ur.user_id WHERE ur.role_code='admin' AND u.status='active' AND u.deleted_at IS NULL")
            .fetch_one(&mut *tx).await?;
        if admins <= 1 { return Err(AppError::Conflict); }
    }
    let result = sqlx::query("DELETE FROM user_roles WHERE user_id=$1 AND role_code=$2")
        .bind(target_user_id).bind(&role_code).execute(&mut *tx).await?;
    if result.rows_affected() == 0 { return Err(AppError::NotFound); }
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'role.removed','user',$2,$3)")
        .bind(actor.user_id).bind(target_user_id.to_string()).bind(json!({"role_code":role_code})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"success","message":"Role removed"})))
}
