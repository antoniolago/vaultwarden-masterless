use actix_web::{HttpResponse, ResponseError};

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::AuthError(msg) => HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "unauthorized",
                "error_description": msg
            })),
            AppError::NotFound(msg) => HttpResponse::NotFound().json(serde_json::json!({
                "error": "not_found",
                "error_description": msg
            })),
            AppError::BadRequest(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "bad_request",
                "error_description": msg
            })),
            AppError::Conflict(msg) => HttpResponse::Conflict().json(serde_json::json!({
                "error": "conflict",
                "error_description": msg
            })),
            AppError::CryptoError(msg) => {
                tracing::error!("Crypto error: {msg}");
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "internal_error",
                    "error_description": "Encryption operation failed"
                }))
            }
            AppError::DatabaseError(msg) => {
                tracing::error!("Database error: {msg}");
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "internal_error",
                    "error_description": "Database operation failed"
                }))
            }
            AppError::InternalError(msg) => {
                tracing::error!("Internal error: {msg}");
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "internal_error",
                    "error_description": "An internal error occurred"
                }))
            }
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
