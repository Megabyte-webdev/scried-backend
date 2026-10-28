use crate::{error::AppError, middleware::CurrentUser, rbac, state::AppState};
use axum::{body::Body, extract::{Multipart, Path, State}, http::{header, HeaderValue, StatusCode}, response::Response, Extension, Json};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::path::{Path as FsPath, PathBuf};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub struct VerificationDecision { pub decision: String, pub note: Option<String> }

#[derive(ToSchema)]
pub struct UploadProofRequest {
    pub kind: String,
    #[schema(value_type = String, format = Binary)]
    pub file: String,
}

#[utoipa::path(post, path = "/api/v1/applications/{application_id}/proofs", tag = "Proofs", summary = "Upload private evidence for an application", params(("application_id" = Uuid, Path)), request_body(content = UploadProofRequest, content_type = "multipart/form-data"), security(("bearerAuth" = [])), responses((status = 200, description = "Proof uploaded")))]
pub async fn upload(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(application_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, AppError> {
    let owner_row = sqlx::query("SELECT user_id FROM applications WHERE id=$1 AND status='active'")
        .bind(application_id).fetch_optional(&state.db).await?;
    let Some(owner_row) = owner_row else { return Err(AppError::NotFound); };
    let application_owner: Option<Uuid> = owner_row.try_get("user_id").map_err(|_| AppError::Internal)?;
    if application_owner != Some(user.user_id) { return Err(AppError::Forbidden); }

    let mut kind: Option<String> = None;
    let mut upload: Option<(String, Vec<u8>)> = None;
    while let Some(field) = multipart.next_field().await.map_err(|_| AppError::BadRequest("Invalid multipart request"))? {
        let field_name = field.name().unwrap_or_default().to_string();
        if field_name == "kind" {
            let value = field.text().await.map_err(|_| AppError::BadRequest("Invalid proof kind"))?;
            kind = Some(value);
        } else if field_name == "file" {
            let name = field.file_name().unwrap_or("proof-upload").to_string();
            let bytes = field.bytes().await.map_err(|_| AppError::BadRequest("Could not read uploaded file"))?;
            if bytes.len() > state.config.max_upload_bytes { return Err(AppError::Validation("Proof files must not exceed 5 MiB".to_string())); }
            upload = Some((name, bytes.to_vec()));
        }
    }
    let kind = kind.ok_or(AppError::BadRequest("Multipart field 'kind' is required"))?;
    if !["activation_screenshot", "certificate", "completion_evidence", "other"].contains(&kind.as_str()) { return Err(AppError::Validation("Unsupported proof kind".to_string())); }
    let (incoming_name, bytes) = upload.ok_or(AppError::BadRequest("Multipart field 'file' is required"))?;
    if bytes.is_empty() { return Err(AppError::Validation("Uploaded file is empty".to_string())); }
    let (mime, extension) = detect_allowed_file(&bytes).ok_or_else(|| AppError::Validation("Only genuine PDF, PNG, and JPEG files are accepted".to_string()))?;
    let safe_name = sanitize_filename(&incoming_name);
    let id = Uuid::new_v4();
    let object_key = format!("{}/{}.{}", application_id, id, extension);
    let path = safe_storage_path(&state.config.private_storage_dir, &object_key)?;
    if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await?; }
    tokio::fs::write(&path, &bytes).await?;
    let digest = Sha256::digest(&bytes).to_vec();
    let insert = sqlx::query("INSERT INTO proofs(id,application_id,uploaded_by,kind,original_filename,mime_type,size_bytes,object_key,sha256) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,status,created_at")
        .bind(id).bind(application_id).bind(user.user_id).bind(&kind).bind(&safe_name).bind(mime).bind(bytes.len() as i64).bind(&object_key).bind(digest)
        .fetch_one(&state.db).await;
    let row = match insert {
        Ok(row) => row,
        Err(err) => { let _ = tokio::fs::remove_file(&path).await; return Err(map_conflict(err)); }
    };
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'proof.uploaded','proof',$2,$3)")
        .bind(user.user_id).bind(id.to_string()).bind(json!({"application_id":application_id,"kind":kind,"size_bytes":bytes.len()})).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","message":"Proof uploaded and queued for review","data":{"id":row.try_get::<Uuid,_>("id").map_err(|_| AppError::Internal)?,"application_id":application_id,"kind":kind,"status":row.try_get::<String,_>("status").map_err(|_| AppError::Internal)?,"created_at":row.try_get::<chrono::DateTime<Utc>,_>("created_at").map_err(|_| AppError::Internal)?}})))
}

#[utoipa::path(get, path = "/api/v1/proofs/{proof_id}/download", tag = "Proofs", summary = "Download an authorized private proof file", params(("proof_id" = Uuid, Path)), security(("bearerAuth" = [])), responses((status = 200, description = "Private proof file returned")))]
pub async fn download(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(proof_id): Path<Uuid>,
) -> Result<Response, AppError> {
    let row = sqlx::query("SELECT p.object_key,p.original_filename,p.mime_type,p.storage_deleted_at,a.user_id AS application_owner FROM proofs p JOIN applications a ON a.id=p.application_id WHERE p.id=$1")
        .bind(proof_id).fetch_optional(&state.db).await?;
    let Some(row) = row else { return Err(AppError::NotFound); };
    let owner: Option<Uuid> = row.try_get("application_owner").map_err(|_| AppError::Internal)?;
    let roles = rbac::roles_for(&state, user.user_id).await?;
    if owner != Some(user.user_id) && !roles.iter().any(|r| ["verifier", "program_manager", "admin"].contains(&r.as_str())) { return Err(AppError::Forbidden); }
    let deleted_at: Option<chrono::DateTime<Utc>> = row.try_get("storage_deleted_at").map_err(|_| AppError::Internal)?;
    if deleted_at.is_some() { return Err(AppError::NotFound); }
    let object_key: String = row.try_get("object_key").map_err(|_| AppError::Internal)?;
    let path = safe_storage_path(&state.config.private_storage_dir, &object_key)?;
    let bytes = tokio::fs::read(path).await.map_err(|_| AppError::NotFound)?;
    let mime: String = row.try_get("mime_type").map_err(|_| AppError::Internal)?;
    let filename: String = row.try_get("original_filename").map_err(|_| AppError::Internal)?;
    let content_type = HeaderValue::from_str(&mime).map_err(|_| AppError::Internal)?;
    let safe_download_name: String = filename.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
        .take(120).collect();
    let safe_download_name = if safe_download_name.trim().is_empty() { "proof-upload" } else { safe_download_name.as_str() };
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{}\"", safe_download_name)).map_err(|_| AppError::Internal)?;
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(header::CONTENT_TYPE, content_type);
    response.headers_mut().insert(header::CONTENT_DISPOSITION, disposition);
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    Ok(response)
}

#[utoipa::path(post, path = "/api/v1/proofs/{proof_id}/decision", tag = "Proofs", summary = "Record a proof verification decision", params(("proof_id" = Uuid, Path)), request_body = VerificationDecision, security(("bearerAuth" = [])), responses((status = 200, description = "Verification decision recorded")))]
pub async fn decide(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path(proof_id): Path<Uuid>,
    Json(input): Json<VerificationDecision>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["verifier", "admin"]).await?;
    if !["approved", "rejected"].contains(&input.decision.as_str()) { return Err(AppError::Validation("decision must be approved or rejected".to_string())); }
    let note = input.note.map(|value| value.trim().chars().take(1000).collect::<String>()).filter(|value| !value.is_empty());
    if input.decision == "rejected" && note.is_none() { return Err(AppError::Validation("A rejection note is required".to_string())); }
    let mut tx = state.db.begin().await?;
    let proof = sqlx::query("SELECT id,application_id,kind,status FROM proofs WHERE id=$1 FOR UPDATE")
        .bind(proof_id).fetch_optional(&mut *tx).await?;
    let Some(proof) = proof else { return Err(AppError::NotFound); };
    let status: String = proof.try_get("status").map_err(|_| AppError::Internal)?;
    if status != "pending" { return Err(AppError::Conflict); }
    let application_id: Uuid = proof.try_get("application_id").map_err(|_| AppError::Internal)?;
    let kind: String = proof.try_get("kind").map_err(|_| AppError::Internal)?;
    let accepted = input.decision == "approved";
    let delete_after = if kind == "activation_screenshot" { Some(Utc::now() + Duration::days(30)) } else { None };
    sqlx::query("UPDATE proofs SET status=$2,reviewer_note=$3,reviewed_by=$4,reviewed_at=now(),delete_after=$5 WHERE id=$1")
        .bind(proof_id).bind(&input.decision).bind(note.as_deref()).bind(actor.user_id).bind(delete_after).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO verification_decisions(proof_id,application_id,verifier_id,decision,note) VALUES ($1,$2,$3,$4,$5)")
        .bind(proof_id).bind(application_id).bind(actor.user_id).bind(&input.decision).bind(note.as_deref()).execute(&mut *tx).await?;
    let stage_updated = accepted && matches!(kind.as_str(), "activation_screenshot" | "certificate" | "completion_evidence");
    if stage_updated {
        let new_stage = match kind.as_str() {
            "activation_screenshot" => "activated",
            "completion_evidence" => "completed",
            "certificate" => "verified",
            _ => unreachable!("stage_updated limits proof kinds"),
        };
        sqlx::query("UPDATE applications SET stage=CASE WHEN CASE stage WHEN 'registered' THEN 1 WHEN 'guided' THEN 2 WHEN 'activated' THEN 3 WHEN 'completed' THEN 4 WHEN 'verified' THEN 5 WHEN 'engaged' THEN 6 ELSE 1 END < CASE $2 WHEN 'registered' THEN 1 WHEN 'guided' THEN 2 WHEN 'activated' THEN 3 WHEN 'completed' THEN 4 WHEN 'verified' THEN 5 WHEN 'engaged' THEN 6 ELSE 1 END THEN $2 ELSE stage END,updated_at=now() WHERE id=$1")
            .bind(application_id).bind(new_stage).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,$2,'proof',$3,$4)")
        .bind(actor.user_id).bind(if accepted {"proof.approved"} else {"proof.rejected"}).bind(proof_id.to_string()).bind(json!({"application_id":application_id,"kind":kind,"note":note})).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(json!({"status":"success","message":"Verification decision saved","data":{"proof_id":proof_id,"application_id":application_id,"decision":input.decision,"stage_updated":stage_updated}})))
}

fn detect_allowed_file(bytes: &[u8]) -> Option<(&'static str, &'static str)> {
    if bytes.starts_with(b"%PDF-") { Some(("application/pdf", "pdf")) }
    else if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) { Some(("image/png", "png")) }
    else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) { Some(("image/jpeg", "jpg")) }
    else { None }
}

fn sanitize_filename(filename: &str) -> String {
    let basename = FsPath::new(filename).file_name().and_then(|s| s.to_str()).unwrap_or("proof-upload");
    let safe: String = basename.chars().filter(|c| !c.is_control() && *c != '/' && *c != '\\').take(120).collect();
    if safe.trim().is_empty() { "proof-upload".to_string() } else { safe }
}

pub fn safe_storage_path(root: &FsPath, key: &str) -> Result<PathBuf, AppError> {
    if key.is_empty() || key.starts_with('/') || key.contains("..") || key.contains('\\') { return Err(AppError::BadRequest("Invalid storage key")); }
    // All object keys are generated by this service; canonicalise the parent to prevent traversal.
    let root = root.canonicalize().or_else(|_| std::fs::create_dir_all(root).and_then(|_| root.canonicalize())).map_err(|_| AppError::Internal)?;
    let candidate = root.join(key);
    if !candidate.starts_with(&root) { return Err(AppError::BadRequest("Invalid storage key")); }
    Ok(candidate)
}

fn map_conflict(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db_error) = &error { if db_error.code().as_deref() == Some("23505") { return AppError::Conflict; } }
    AppError::Database(error)
}


pub async fn delete_private_file(root: &FsPath, key: &str) -> Result<(), AppError> {
    let path = safe_storage_path(root, key)?;
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AppError::from(error)),
    }
}

#[utoipa::path(get, path = "/api/v1/proofs/queue", tag = "Proofs", summary = "List proofs awaiting review", security(("bearerAuth" = [])), responses((status = 200, description = "Proof review queue returned")))]
pub async fn queue(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["verifier", "admin"]).await?;
    let page = query.get("page").and_then(|v| v.parse::<i64>().ok()).unwrap_or(1).max(1);
    let page_size = query.get("page_size").and_then(|v| v.parse::<i64>().ok()).unwrap_or(20).clamp(1, 50);
    let offset = (page - 1) * page_size;
    let rows = sqlx::query("SELECT p.id,p.application_id,p.kind,p.original_filename,p.mime_type,p.size_bytes,p.created_at,a.email,a.registration_snapshot,o.title AS opportunity_title FROM proofs p JOIN applications a ON a.id=p.application_id JOIN opportunities o ON o.id=a.opportunity_id WHERE p.status='pending' ORDER BY p.created_at ASC LIMIT $1 OFFSET $2")
        .bind(page_size).bind(offset).fetch_all(&state.db).await?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM proofs WHERE status='pending'").fetch_one(&state.db).await?;
    let items = rows.into_iter().map(|row| json!({
        "id":row.try_get::<Uuid,_>("id").ok(),"application_id":row.try_get::<Uuid,_>("application_id").ok(),"kind":row.try_get::<String,_>("kind").ok(),
        "filename":row.try_get::<String,_>("original_filename").ok(),"mime_type":row.try_get::<String,_>("mime_type").ok(),"size_bytes":row.try_get::<i64,_>("size_bytes").ok(),
        "created_at":row.try_get::<chrono::DateTime<Utc>,_>("created_at").ok(),"email":row.try_get::<String,_>("email").ok(),
        "student":row.try_get::<serde_json::Value,_>("registration_snapshot").ok(),"opportunity_title":row.try_get::<String,_>("opportunity_title").ok()
    })).collect::<Vec<_>>();
    Ok(Json(json!({"status":"success","data":{"items":items,"page":page,"page_size":page_size,"total":total}})))
}

pub async fn cleanup_expired(state: &AppState) -> Result<u64, AppError> {
    let rows = sqlx::query("SELECT id,object_key FROM proofs WHERE delete_after IS NOT NULL AND delete_after <= now() AND storage_deleted_at IS NULL ORDER BY delete_after ASC LIMIT 100")
        .fetch_all(&state.db).await?;
    let mut cleaned = 0_u64;
    for row in rows {
        let id: Uuid = row.try_get("id").map_err(|_| AppError::Internal)?;
        let key: String = row.try_get("object_key").map_err(|_| AppError::Internal)?;
        match delete_private_file(&state.config.private_storage_dir, &key).await {
            Ok(()) => {
                sqlx::query("UPDATE proofs SET storage_deleted_at=now(),object_key='deleted/'||id::text,original_filename='deleted',sha256=decode(repeat('00',32),'hex') WHERE id=$1 AND storage_deleted_at IS NULL")
                    .bind(id).execute(&state.db).await?;
                cleaned += 1;
            }
            Err(error) => tracing::error!(proof_id = %id, error = %error, "proof retention cleanup failed"),
        }
    }
    Ok(cleaned)
}
