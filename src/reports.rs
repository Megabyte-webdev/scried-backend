use crate::{error::AppError, middleware::CurrentUser, rbac, state::AppState};
use axum::{body::Body, extract::{Path, Query, State}, http::{header, HeaderValue, StatusCode}, response::Response, Extension, Json};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Deserialize, Default)]
pub struct ReportFilters {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    /// Calendar quarter in the form `2026-Q3`. If supplied, explicit `from`/`to` are not allowed.
    pub quarter: Option<String>,
    pub school: Option<String>,
    pub state: Option<String>,
    pub level: Option<String>,
    pub age_range: Option<String>,
    pub course: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/reports/opportunities/{opportunity_id}/funnel",
    tag = "Reports",
    summary = "Get application funnel metrics",
    params(
        ("opportunity_id" = Uuid, Path),
        ("from" = Option<DateTime<Utc>>, Query),
        ("to" = Option<DateTime<Utc>>, Query),
        ("quarter" = Option<String>, Query, description = "Calendar quarter, for example 2026-Q3"),
        ("school" = Option<String>, Query),
        ("state" = Option<String>, Query),
        ("level" = Option<String>, Query),
        ("age_range" = Option<String>, Query),
        ("course" = Option<String>, Query)
    ),
    security(("bearerAuth" = [])),
    responses((status = 200, description = "Funnel report returned"))
)]
pub async fn funnel(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path(opportunity_id): Path<Uuid>,
    Query(filters): Query<ReportFilters>,
) -> Result<Json<serde_json::Value>, AppError> {
    rbac::require_any_role(&state, &actor, &["program_manager", "admin"]).await?;
    let (from, to) = effective_range(&filters)?;
    let school = clean_filter(&filters.school);
    let state_filter = clean_filter(&filters.state);
    let level = clean_filter(&filters.level);
    let age_range = clean_filter(&filters.age_range);
    let course = clean_filter(&filters.course);
    let opportunity = sqlx::query("SELECT title,value_ngn FROM opportunities WHERE id=$1")
        .bind(opportunity_id).fetch_optional(&state.db).await?;
    let Some(opportunity) = opportunity else { return Err(AppError::NotFound); };
    let title: String = opportunity.try_get("title").map_err(|_| AppError::Internal)?;
    let value_ngn: Option<i64> = opportunity.try_get("value_ngn").map_err(|_| AppError::Internal)?;

    let predicate = "opportunity_id=$1 AND status='active' AND ($2::timestamptz IS NULL OR registered_at >= $2) AND ($3::timestamptz IS NULL OR registered_at < $3) AND ($4::text IS NULL OR registration_snapshot->>'school_name'=$4) AND ($5::text IS NULL OR registration_snapshot->>'state'=$5) AND ($6::text IS NULL OR registration_snapshot->>'level'=$6) AND ($7::text IS NULL OR registration_snapshot->>'age_range'=$7) AND ($8::text IS NULL OR registration_snapshot->>'course'=$8)";
    let aggregate_sql = format!(
        "SELECT COUNT(*) AS registered, COUNT(*) FILTER (WHERE clicked_through_at IS NOT NULL) AS clicked, COUNT(*) FILTER (WHERE stage IN ('guided','activated','completed','verified','engaged')) AS guided, COUNT(*) FILTER (WHERE stage IN ('activated','completed','verified','engaged')) AS activated, COUNT(*) FILTER (WHERE stage IN ('completed','verified','engaged')) AS completed, COUNT(*) FILTER (WHERE stage IN ('verified','engaged')) AS verified, COUNT(*) FILTER (WHERE stage='engaged') AS engaged FROM applications WHERE {predicate}"
    );
    let row = sqlx::query(&aggregate_sql)
        .bind(opportunity_id).bind(from.clone()).bind(to.clone()).bind(&school).bind(&state_filter).bind(&level).bind(&age_range).bind(&course)
        .fetch_one(&state.db).await?;
    let registered: i64 = row.try_get("registered").map_err(|_| AppError::Internal)?;
    let clicked: i64 = row.try_get("clicked").map_err(|_| AppError::Internal)?;
    let guided: i64 = row.try_get("guided").map_err(|_| AppError::Internal)?;
    let activated: i64 = row.try_get("activated").map_err(|_| AppError::Internal)?;
    let completed: i64 = row.try_get("completed").map_err(|_| AppError::Internal)?;
    let verified: i64 = row.try_get("verified").map_err(|_| AppError::Internal)?;
    let engaged: i64 = row.try_get("engaged").map_err(|_| AppError::Internal)?;

    let school_sql = format!(
        "SELECT COALESCE(NULLIF(registration_snapshot->>'school_name',''),'Not supplied') AS school_name, COUNT(*) AS registrations, COUNT(*) FILTER (WHERE stage IN ('completed','verified','engaged')) AS completions, COUNT(*) FILTER (WHERE stage IN ('verified','engaged')) AS verified FROM applications WHERE {predicate} GROUP BY COALESCE(NULLIF(registration_snapshot->>'school_name',''),'Not supplied') ORDER BY registrations DESC LIMIT 500"
    );
    let school_rows = sqlx::query(&school_sql)
        .bind(opportunity_id).bind(from.clone()).bind(to.clone()).bind(&school).bind(&state_filter).bind(&level).bind(&age_range).bind(&course)
        .fetch_all(&state.db).await?;
    let mut school_scores = school_rows.into_iter().map(|r| {
        let name: String = r.try_get("school_name").unwrap_or_else(|_| "Not supplied".to_string());
        let registrations: i64 = r.try_get("registrations").unwrap_or(0);
        let completions: i64 = r.try_get("completions").unwrap_or(0);
        let verified: i64 = r.try_get("verified").unwrap_or(0);
        let score = registrations.saturating_add(completions.saturating_mul(2)).saturating_add(verified.saturating_mul(3));
        (name, registrations, completions, verified, score)
    }).collect::<Vec<_>>();
    school_scores.sort_by(|a, b| b.4.cmp(&a.4));
    let number_of_schools = school_scores.len();
    let school_breakdown = school_scores.iter().map(|(name, registrations, completions, verified, score)| {
        let lower = school_scores.iter().filter(|other| other.4 < *score).count();
        let percentile = if number_of_schools <= 1 { 100.0 } else { (lower as f64 * 100.0 / (number_of_schools - 1) as f64 * 100.0).round() / 100.0 };
        json!({"school_name":name,"registrations":registrations,"completions":completions,"verified":verified,"school_score":score,"percentile":percentile})
    }).collect::<Vec<_>>();

    let value_unlocked_ngn = value_ngn.unwrap_or(0).saturating_mul(activated);
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'report.viewed','opportunity',$2,$3)")
        .bind(actor.user_id).bind(opportunity_id.to_string()).bind(json!({"report":"funnel","has_date_filter":from.is_some() || to.is_some(),"has_dimension_filter":school.is_some() || state_filter.is_some() || level.is_some() || age_range.is_some() || course.is_some()})).execute(&state.db).await?;
    Ok(Json(json!({"status":"success","data":{
        "opportunity":{"id":opportunity_id,"title":title,"value_ngn":value_ngn},
        "filters":{"from":from,"to_exclusive":to,"school":school,"state":state_filter,"level":level,"age_range":age_range,"course":course,"quarter":filters.quarter},
        "funnel":{"registered":registered,"guided":guided,"activated":activated,"completed":completed,"verified":verified,"engaged":engaged,"clicked_through":clicked},
        "rates":{"click_through_percent":percent(clicked,registered),"activation_percent":percent(activated,registered),"completion_percent":percent(completed,registered),"verification_percent":percent(verified,registered)},
        "value_unlocked_ngn":value_unlocked_ngn,
        "school_breakdown":school_breakdown,
        "generated_at":Utc::now()
    }})))
}

#[utoipa::path(
    get,
    path = "/api/v1/reports/opportunities/{opportunity_id}/applications.csv",
    tag = "Reports",
    summary = "Export opportunity applications as CSV",
    params(
        ("opportunity_id" = Uuid, Path),
        ("from" = Option<DateTime<Utc>>, Query),
        ("to" = Option<DateTime<Utc>>, Query),
        ("quarter" = Option<String>, Query, description = "Calendar quarter, for example 2026-Q3"),
        ("school" = Option<String>, Query),
        ("state" = Option<String>, Query),
        ("level" = Option<String>, Query),
        ("age_range" = Option<String>, Query),
        ("course" = Option<String>, Query)
    ),
    security(("bearerAuth" = [])),
    responses((status = 200, description = "CSV report returned", content_type = "text/csv"))
)]
pub async fn applications_csv(
    State(state): State<AppState>,
    Extension(actor): Extension<CurrentUser>,
    Path(opportunity_id): Path<Uuid>,
    Query(filters): Query<ReportFilters>,
) -> Result<Response, AppError> {
    rbac::require_any_role(&state, &actor, &["program_manager", "admin"]).await?;
    let (from, to) = effective_range(&filters)?;
    let school = clean_filter(&filters.school);
    let state_filter = clean_filter(&filters.state);
    let level = clean_filter(&filters.level);
    let age_range = clean_filter(&filters.age_range);
    let course = clean_filter(&filters.course);
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM opportunities WHERE id=$1)")
        .bind(opportunity_id).fetch_one(&state.db).await?;
    if !exists { return Err(AppError::NotFound); }
    let sql = "SELECT id,registration_snapshot->>'full_name' AS full_name,email,registration_snapshot->>'school_name' AS school_name,registration_snapshot->>'course' AS course,registration_snapshot->>'level' AS level,stage,registered_at,clicked_through_at FROM applications WHERE opportunity_id=$1 AND status='active' AND ($2::timestamptz IS NULL OR registered_at >= $2) AND ($3::timestamptz IS NULL OR registered_at < $3) AND ($4::text IS NULL OR registration_snapshot->>'school_name'=$4) AND ($5::text IS NULL OR registration_snapshot->>'state'=$5) AND ($6::text IS NULL OR registration_snapshot->>'level'=$6) AND ($7::text IS NULL OR registration_snapshot->>'age_range'=$7) AND ($8::text IS NULL OR registration_snapshot->>'course'=$8) ORDER BY registered_at DESC";
    let rows = sqlx::query(sql).bind(opportunity_id).bind(from.clone()).bind(to.clone()).bind(&school).bind(&state_filter).bind(&level).bind(&age_range).bind(&course).fetch_all(&state.db).await?;
    let mut writer = csv::Writer::from_writer(Vec::<u8>::new());
    writer.write_record(["application_id","full_name","email","school_name","course","level","stage","registered_at","clicked_through_at"])
        .map_err(|_| AppError::Internal)?;
    for row in rows {
        let record = [
            row.try_get::<Uuid,_>("id").map_err(|_| AppError::Internal)?.to_string(),
            safe_csv_cell(row.try_get::<Option<String>,_>("full_name").map_err(|_| AppError::Internal)?.unwrap_or_default()),
            safe_csv_cell(row.try_get::<String,_>("email").map_err(|_| AppError::Internal)?),
            safe_csv_cell(row.try_get::<Option<String>,_>("school_name").map_err(|_| AppError::Internal)?.unwrap_or_default()),
            safe_csv_cell(row.try_get::<Option<String>,_>("course").map_err(|_| AppError::Internal)?.unwrap_or_default()),
            safe_csv_cell(row.try_get::<Option<String>,_>("level").map_err(|_| AppError::Internal)?.unwrap_or_default()),
            row.try_get::<String,_>("stage").map_err(|_| AppError::Internal)?,
            row.try_get::<DateTime<Utc>,_>("registered_at").map_err(|_| AppError::Internal)?.to_rfc3339(),
            row.try_get::<Option<DateTime<Utc>>,_>("clicked_through_at").map_err(|_| AppError::Internal)?.map(|v| v.to_rfc3339()).unwrap_or_default(),
        ];
        writer.write_record(record).map_err(|_| AppError::Internal)?;
    }
    let bytes = writer.into_inner().map_err(|_| AppError::Internal)?;
    sqlx::query("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'report.exported','opportunity',$2,$3)")
        .bind(actor.user_id).bind(opportunity_id.to_string()).bind(json!({"format":"csv","contains_personal_data":true,"from":from,"to_exclusive":to})).execute(&state.db).await?;
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
    response.headers_mut().insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=\"scried-opportunity-applications.csv\""));
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response.headers_mut().insert(header::HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
    Ok(response)
}

fn effective_range(filters: &ReportFilters) -> Result<(Option<DateTime<Utc>>, Option<DateTime<Utc>>), AppError> {
    let (from, to) = if let Some(quarter) = filters.quarter.as_deref() {
        if filters.from.is_some() || filters.to.is_some() {
            return Err(AppError::Validation("Use either quarter or from/to, not both".to_string()));
        }
        let (year_str, quarter_str) = quarter.split_once("-Q").ok_or_else(|| AppError::Validation("quarter must use YYYY-Qn format".to_string()))?;
        let year = year_str.parse::<i32>().map_err(|_| AppError::Validation("Invalid quarter year".to_string()))?;
        let quarter_num = quarter_str.parse::<u32>().map_err(|_| AppError::Validation("Invalid quarter number".to_string()))?;
        if !(1..=4).contains(&quarter_num) || !(2000..=2200).contains(&year) {
            return Err(AppError::Validation("quarter must be between 2000-Q1 and 2200-Q4".to_string()));
        }
        let month = (quarter_num - 1) * 3 + 1;
        let start = NaiveDate::from_ymd_opt(year, month, 1).and_then(|d| d.and_hms_opt(0, 0, 0)).map(|d| d.and_utc())
            .ok_or_else(|| AppError::Validation("Invalid quarter start".to_string()))?;
        let (next_year, next_month) = if quarter_num == 4 { (year + 1, 1) } else { (year, month + 3) };
        let end = NaiveDate::from_ymd_opt(next_year, next_month, 1).and_then(|d| d.and_hms_opt(0, 0, 0)).map(|d| d.and_utc())
            .ok_or_else(|| AppError::Validation("Invalid quarter end".to_string()))?;
        (Some(start), Some(end))
    } else {
        (filters.from.clone(), filters.to.clone())
    };
    if let (Some(start), Some(end)) = (from.as_ref(), to.as_ref()) {
        if end <= start { return Err(AppError::Validation("to must be later than from".to_string())); }
    }
    Ok((from, to))
}

fn clean_filter(value: &Option<String>) -> Option<String> {
    value.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(160).collect())
}

fn safe_csv_cell(value: String) -> String {
    let trimmed = value.trim_start();
    if trimmed.starts_with('=') || trimmed.starts_with('+') || trimmed.starts_with('-') || trimmed.starts_with('@') {
        format!("'{value}")
    } else { value }
}

fn percent(numerator: i64, denominator: i64) -> f64 {
    if denominator == 0 { 0.0 } else { (numerator as f64 * 100.0 / denominator as f64 * 100.0).round() / 100.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarter_filter_uses_inclusive_start_and_exclusive_next_quarter() {
        let filters = ReportFilters { quarter: Some("2026-Q3".to_string()), ..ReportFilters::default() };
        let (start, end) = effective_range(&filters).expect("valid quarter");
        assert_eq!(start.expect("quarter start").format("%Y-%m-%d %H:%M:%S").to_string(), "2026-07-01 00:00:00");
        assert_eq!(end.expect("quarter end").format("%Y-%m-%d %H:%M:%S").to_string(), "2026-10-01 00:00:00");
    }

    #[test]
    fn quarter_filter_rejects_mixed_ranges_and_invalid_quarters() {
        let mixed = ReportFilters {
            from: Some(Utc::now()),
            quarter: Some("2026-Q2".to_string()),
            ..ReportFilters::default()
        };
        assert!(effective_range(&mixed).is_err());
        let invalid = ReportFilters { quarter: Some("2026-Q9".to_string()), ..ReportFilters::default() };
        assert!(effective_range(&invalid).is_err());
    }

    #[test]
    fn spreadsheet_formula_prefixes_are_neutralised() {
        assert_eq!(safe_csv_cell("=1+1".to_string()), "'=1+1");
        assert_eq!(safe_csv_cell("  @SUM(A1:A2)".to_string()), "'  @SUM(A1:A2)");
        assert_eq!(safe_csv_cell("student@example.org".to_string()), "student@example.org");
    }
}
