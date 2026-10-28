use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid request")]
    BadRequest(&'static str),
    #[error("validation failed")]
    Validation(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("permission denied")]
    Forbidden,
    #[error("resource not found")]
    NotFound,
    #[error("resource conflict")]
    Conflict,
    #[error("request limit exceeded")]
    TooManyRequests,
    #[error("service temporarily unavailable")]
    Unavailable,
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    #[error("internal server error")]
    Internal,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message.to_string()),
            Self::Validation(message) => (StatusCode::UNPROCESSABLE_ENTITY, "validation_error", message),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "Authentication is required or the credentials are invalid".to_string()),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "You do not have permission to perform this action".to_string()),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "The requested resource was not found".to_string()),
            Self::Conflict => (StatusCode::CONFLICT, "conflict", "The request conflicts with the current resource state".to_string()),
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many requests. Please try again later".to_string()),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable", "A required service is temporarily unavailable".to_string()),
            Self::Database(err) => {
                tracing::error!(error = %err, "database operation failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An unexpected error occurred".to_string())
            }
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "An unexpected error occurred".to_string()),
        };
        (status, Json(ErrorBody { error: code, message })).into_response()
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        tracing::error!(error = %err, "storage operation failed");
        Self::Internal
    }
}
