use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::auth;
use crate::config::Config;
use crate::crypto::VaultKeyManager;
use crate::db::Database;
use crate::errors::{AppError, AppResult};
use crate::models::{KeyEnrollPayload, KeyRetrievalPayload};

/// Shared application state passed to all handlers.
pub struct AppState {
    pub db: Arc<Database>,
    pub crypto: Arc<VaultKeyManager>,
    pub config: Arc<Config>,
    pub vw_decoding_key: jsonwebtoken::DecodingKey,
    pub http_client: reqwest::Client,
    /// Maps SSO state → VW_SSO_BINDING cookie value.
    /// Istio Gateway strips Cookie headers on HTTPS→HTTP, so we
    /// capture the cookie from authorize responses and inject it
    /// on oidc-signin callbacks.
    pub sso_cookies: Mutex<HashMap<String, String>>,
    /// Vaultwarden version detected at runtime (refreshed in the background).
    /// `None` means we could not reach Vaultwarden.
    pub vw_version: Mutex<Option<String>>,
}

// GET /alive — health check
pub async fn alive() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "alive": true,
        "now": Utc::now().to_rfc3339()
    }))
}

// GET /version — version info + compatibility matrix
pub async fn version(state: web::Data<AppState>) -> HttpResponse {
    use crate::models::{ClientVersions, CompatibilityInfo, VersionResponse};

    // Vaultwarden version detected at runtime (None when unreachable)
    let detected = state.vw_version.lock().await.clone();

    // Parse the compat_clients JSON (or use defaults on parse failure)
    let clients: ClientVersions = serde_json::from_str(&state.config.compat_clients)
        .unwrap_or_else(|_| ClientVersions {
            web: "untested".into(),
            desktop: "untested".into(),
            browser_extension: "untested".into(),
            mobile: "untested".into(),
        });

    let resp = VersionResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        build: if state.config.build_sha.is_empty() {
            "dev".into()
        } else {
            state.config.build_sha.clone()
        },
        compatibility: CompatibilityInfo {
            vaultwarden: state.config.compat_vw_version.clone(),
            vaultwarden_detected: detected.clone(),
            status: crate::version_probe::status_for(
                detected.as_deref(),
                &state.config.compat_vw_version,
            )
            .to_string(),
            keycloak: state.config.compat_kc_version.clone(),
            clients,
            last_tested: state.config.compat_last_tested.clone(),
            status_url: state.config.compat_status_url.clone(),
        },
        alive: true,
    };

    HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("X-Vaultwarden-Masterless-Version", env!("CARGO_PKG_VERSION")))
        .json(resp)
}

// GET /user-keys — retrieve the user's decryption key
pub async fn get_user_key(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> AppResult<HttpResponse> {
    let user = auth::authenticate_request(&req, &state.vw_decoding_key, &state.config).await?;

    let record = state
        .db
        .get_user_key(&user.user_id)?
        .ok_or_else(|| AppError::NotFound(format!("No key stored for user {}", user.user_id)))?;

    // Update last access timestamp
    let _ = state.db.touch_user_key_access(&user.user_id);

    let decrypted_key = state.crypto.unseal_vault_key(&record.encrypted_key)?;

    tracing::info!("Key retrieved for user {}", user.user_id);

    Ok(HttpResponse::Ok()
        .insert_header(("Cache-Control", "no-store, no-cache, must-revalidate"))
        .insert_header(("Pragma", "no-cache"))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .json(KeyRetrievalPayload { key: decrypted_key }))
}

// POST /user-keys — store the user's encryption key (idempotent enrollment)
//
// The Bitwarden web vault calls POST /user-keys for BOTH new and returning
// key-connector users. For returning users, the key already exists — return
// the stored key instead of rejecting with 409.
pub async fn post_user_key(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<KeyEnrollPayload>,
) -> AppResult<HttpResponse> {
    let user = auth::authenticate_request(&req, &state.vw_decoding_key, &state.config).await?;

    if let Some(record) = state.db.get_user_key(&user.user_id)? {
        // UK_enc missing means this is a re-enrollment — allow overwrite
        let has_uk_enc = state.db.get_user_encrypted_key(&user.user_id)?.is_some();
        if has_uk_enc {
            let decrypted_key = state.crypto.unseal_vault_key(&record.encrypted_key)?;
            tracing::info!("Key ENROLL (EXISTING) for user {} via POST /user-keys (idempotent)", user.user_id);
            return Ok(HttpResponse::Ok()
                .insert_header(("Cache-Control", "no-store, no-cache, must-revalidate"))
                .insert_header(("Pragma", "no-cache"))
                .insert_header(("X-Content-Type-Options", "nosniff"))
                .json(KeyRetrievalPayload { key: decrypted_key }));
        } else {
            // Re-enrollment: overwrite with new key
            let encrypted = state.crypto.seal_vault_key(&body.key)?;
            state.db.update_user_key(&user.user_id, &encrypted)?;
            tracing::info!("Key ENROLL (RE-ENROLLMENT) for user {} — key overwritten", user.user_id);
            return Ok(HttpResponse::Ok()
                .insert_header(("Cache-Control", "no-store, no-cache, must-revalidate"))
                .insert_header(("Pragma", "no-cache"))
                .insert_header(("X-Content-Type-Options", "nosniff"))
                .json(KeyRetrievalPayload { key: body.key.clone() }));
        }
    }

    let encrypted = state.crypto.seal_vault_key(&body.key)?;
    state.db.insert_user_key(&user.user_id, &encrypted)?;

    tracing::info!("Key enrolled for user {}", user.user_id);

    Ok(HttpResponse::Ok().finish())
}

// PUT /user-keys — update the user's encryption key
pub async fn put_user_key(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<KeyEnrollPayload>,
) -> AppResult<HttpResponse> {
    let user = auth::authenticate_request(&req, &state.vw_decoding_key, &state.config).await?;

    // Verify the user has an existing key
    if state.db.get_user_key(&user.user_id)?.is_none() {
        return Err(AppError::NotFound(format!(
            "No key found for user {}. Use POST to enroll.",
            user.user_id
        )));
    }

    let encrypted = state.crypto.seal_vault_key(&body.key)?;
    state.db.update_user_key(&user.user_id, &encrypted)?;

    tracing::info!("Key updated for user {}", user.user_id);

    Ok(HttpResponse::Ok().finish())
}

// DELETE /user-keys — remove the user's stored key
pub async fn delete_user_key(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> AppResult<HttpResponse> {
    let user = auth::authenticate_request(&req, &state.vw_decoding_key, &state.config).await?;

    let deleted = state.db.delete_user_key(&user.user_id)?;
    if !deleted {
        return Err(AppError::NotFound(format!("No key found for user {}", user.user_id)));
    }

    tracing::info!("Key deleted for user {}", user.user_id);

    Ok(HttpResponse::Ok().finish())
}

#[allow(dead_code)]
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/alive", web::get().to(alive))
        .route("/version", web::get().to(version))
        .route("/user-keys", web::get().to(get_user_key))
        .route("/user-keys", web::post().to(post_user_key))
        .route("/user-keys", web::put().to(put_user_key))
        .route("/user-keys", web::delete().to(delete_user_key));
}
