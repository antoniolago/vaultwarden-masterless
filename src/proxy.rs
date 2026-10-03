use actix_web::{web, HttpRequest, HttpResponse};
use base64::Engine as _;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::api::AppState;

// Detect if this is a WebSocket upgrade request
fn is_websocket_upgrade(req: &HttpRequest) -> bool {
    let upgrade = req.headers().get("upgrade")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let connection = req.headers().get("connection")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    upgrade.eq_ignore_ascii_case("websocket")
        && connection.to_lowercase().contains("upgrade")
}

// Reverse proxy that sits between clients and Vaultwarden.
// Forwards all requests and selectively patches responses to enable
// masterpassword-less SSO login — no Vaultwarden source changes needed.

/// Catch-all proxy handler: forwards the request to Vaultwarden,
/// then patches specific response bodies to enable passwordless support.
pub async fn proxy_handler(
    req: HttpRequest,
    body: web::Payload,
    state: web::Data<AppState>,
) -> HttpResponse {
    let client = &state.http_client;

    let vw_url = state.config.vaultwarden_url.trim_end_matches('/');
    let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or(req.uri().path()).to_string();

    // Handle WebSocket upgrade for SignalR /notifications/hub
    if is_websocket_upgrade(&req) {
        return handle_websocket_proxy(req, body, vw_url, &path).await;
    }

    // Consume body as bytes for HTTP processing
    let body = match body.to_bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Proxy body read error: {e}");
            return HttpResponse::BadRequest().finish();
        }
    };

    // Block admin panel access through the proxy
    let path_lower = req.uri().path().to_lowercase();
    if path_lower.starts_with("/admin") {
        tracing::warn!("Blocked admin panel access attempt: {}", path_lower);
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Not found"}));
    }
    let target_url = format!("{vw_url}{path}");

    // Handle set-key-connector-key by transforming to VW's POST /api/accounts/keys
    let request_path_lower = path_lower;
    if request_path_lower == "/api/accounts/set-key-connector-key" && req.method() == actix_web::http::Method::POST {
        return handle_set_key_connector_key(&req, &body, client, vw_url, &state).await;
    }

    // Handle POST /api/accounts/key — Bitwarden Server endpoint for storing the
    // wrapped symmetric user key (the "Key" or "akey" field).  Stock Vaultwarden
    // does not implement this, so we intercept it here and persist the key in
    // vaultwarden-masterless's /user-keys store.
    if request_path_lower == "/api/accounts/key" && req.method() == actix_web::http::Method::POST {
        return handle_set_user_key(&req, &body, &state).await;
    }

    // Handle key-connector confirmation-details — Bitwarden clients call this
    // during SSO enrollment to confirm the Key Connector domain. Stock
    // Vaultwarden doesn't implement this endpoint (it's a Bitwarden Server
    // feature), so we stub it here to let the client proceed with key enrollment.
    if request_path_lower.starts_with("/api/accounts/key-connector/confirmation-details/")
        && req.method() == actix_web::http::Method::GET
    {
        use crate::auth;
        match auth::authenticate_request(&req, &state.vw_decoding_key, &state.config).await {
            Ok(user) => {
                tracing::info!(
                    "key-connector confirmation-details: authenticated user {} — returning stub response",
                    user.user_id
                );
                return HttpResponse::Ok().json(serde_json::json!({
                    "Object": "keyConnectorConfirmationDetails",
                    "OrganizationName": &state.config.synthetic_org_name
                }));
            }
            Err(e) => {
                tracing::warn!("key-connector confirmation-details: authentication failed: {e}");
                return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
            }
        }
    }

    // Handle convert-to-key-connector — Bitwarden clients call this during SSO
    // enrollment to switch an existing account from master-password to Key
    // Connector mode. Stock Vaultwarden doesn't implement this endpoint (it's a
    // Bitwarden Server feature), so we stub it.
    if request_path_lower == "/api/accounts/convert-to-key-connector"
        && req.method() == actix_web::http::Method::POST
    {
        use crate::auth;
        match auth::authenticate_request(&req, &state.vw_decoding_key, &state.config).await {
            Ok(user) => {
                tracing::info!(
                    "convert-to-key-connector: user {} converted (stub)",
                    user.user_id
                );
                return HttpResponse::Ok().json(serde_json::json!({"success": true}));
            }
            Err(e) => {
                tracing::warn!("convert-to-key-connector: authentication failed: {e}");
                return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication required"}));
            }
        }
    }

    // Build the upstream request
    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut upstream_req = client.request(method, &target_url);

    // Forward all headers (including Host) so Vaultwarden generates
    // proper session cookies with the correct domain and sees the
    // original request context.
    // Inject VW_SSO_BINDING cookie on oidc-signin callbacks when missing.
    // Istio Gateway strips Cookie headers on HTTPS→HTTP downgrade.
    let mut injected_cookie = false;
    if request_path_lower.contains("oidc-signin") {
        let has_binding = req.headers().get_all("cookie").into_iter()
            .any(|v| v.to_str().map(|s| s.contains("VW_SSO_BINDING")).unwrap_or(false));
        if !has_binding {
            // Extract state from URL and look up stored cookie
            if let Some(query) = req.uri().query() {
                for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
                    if k == "state" {
                        let sso_state: String = v.into_owned();
                        let map = state.sso_cookies.lock().await;
                        if let Some(cookie_val) = map.get(&sso_state) {
                            upstream_req = upstream_req.header("Cookie",
                                format!("VW_SSO_BINDING={cookie_val}"));
                            injected_cookie = true;
                        }
                        break;
                    }
                }
            }
        }
    }

    for (key, value) in req.headers() {
        if injected_cookie && key.as_str().eq_ignore_ascii_case("cookie") {
            continue;
        }
        if let Ok(v) = value.to_str() {
            upstream_req = upstream_req.header(key.as_str(), v);
        }
    }

    // Add X-Forwarded headers so Vaultwarden knows the original
    // client IP, protocol (HTTPS), and hostname. Without these,
    // Vaultwarden may generate wrong cookie domains and redirect URLs.
    if let Some(host) = req.headers().get("host").and_then(|v| v.to_str().ok()) {
        upstream_req = upstream_req.header("X-Forwarded-Host", host);
    }
    if let Some(peer) = req.peer_addr() {
        upstream_req = upstream_req.header("X-Forwarded-For", peer.ip().to_string());
    }
    // Detect HTTPS from common reverse proxy headers or TLS info
    let is_https = req.headers().get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "https")
        .unwrap_or(false);
    upstream_req = upstream_req.header("X-Forwarded-Proto", if is_https { "https" } else { "http" });

    // Forward body
    if !body.is_empty() {
        upstream_req = upstream_req.body(body.to_vec());
    }

    // Send upstream
    let upstream_resp = match upstream_req.send().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Proxy upstream error: {e}");
            return HttpResponse::BadGateway().json(serde_json::json!({
                "error": "bad_gateway",
                "error_description": "Failed to reach upstream service"
            }));
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();

    // Read the response body
    let resp_body = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Proxy body read error: {e}");
            return HttpResponse::BadGateway().finish();
        }
    };

    // Determine if we need to patch the response
    let request_path = &request_path_lower;
    let user_keys_url = &state.config.user_keys_url;

    // The Bitwarden client appends "/user-keys" to the KeyConnectorUrl when
    // calling the Key Connector API (see api.service.ts getMasterKeyFromKeyConnector).
    // So we must inject the BASE URL (without /user-keys) — otherwise the client
    // ends up calling ".../user-keys/user-keys" which 404s and logs the user out.
    let key_connector_url = user_keys_url
        .trim_end_matches('/')
        .strip_suffix("/user-keys")
        .unwrap_or(user_keys_url);

    // Capture VW_SSO_BINDING cookie from authorize redirects.
    // Istio Gateway strips Cookie on HTTPS→HTTP, so we store the cookie
    // value keyed by SSO state for injection on the oidc-signin callback.
    if request_path == "/identity/connect/authorize" && status.is_redirection() {
        for (key, value) in resp_headers.iter() {
            if key.as_str().eq_ignore_ascii_case("set-cookie") {
                if let Ok(v) = value.to_str() {
                    if let Some(cookie_val) = v.split(';')
                        .find(|c| c.trim().starts_with("VW_SSO_BINDING="))
                        .and_then(|c| c.trim().strip_prefix("VW_SSO_BINDING="))
                    {
                        if let Some(loc) = resp_headers.get("location")
                            .and_then(|l| l.to_str().ok())
                        {
                            if let Some(s) = loc.split("state=").nth(1)
                                .and_then(|s| s.split('&').next())
                                .map(|s| s.replace("%3D", "=").replace("%3d", "="))
                            {
                                state.sso_cookies.lock().await
                                    .insert(s.to_string(), cookie_val.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    let final_body = if status.is_success() && !user_keys_url.is_empty() {
        let org_name = &state.config.synthetic_org_name;
        let org_id = &state.config.synthetic_org_identifier;

        // A master-password login keeps its master-password semantics (see
        // request_grant_type). Everything else keeps the configured behaviour.
        let password_login = request_path == "/identity/connect/token"
            && request_grant_type(&body).as_deref() == Some("password");

        if password_login {
            tracing::debug!(
                "{request_path}: grant_type=password — passing the response through unpatched"
            );
            resp_body.to_vec()
        } else if request_path == "/identity/connect/token" {
            // Track client version for compatibility monitoring
            track_client_version(&state, &body);
            let user_id = extract_user_id_from_login_response(&resp_body);
            let (user_has_key, user_encrypted_key) = match user_id {
                Some(uid) => {
                    let has_key = state.db.get_user_key(&uid).ok().flatten().is_some();
                    let uk_enc = if has_key {
                        state.db.get_user_encrypted_key(&uid).ok().flatten()
                    } else {
                        None
                    };
                    (has_key, uk_enc)
                }
                None => {
                    tracing::warn!("login-response patch: could not extract user_id from access_token");
                    (false, None)
                }
            };
            patch_login_response(&resp_body, key_connector_url, user_has_key, user_encrypted_key.as_deref())
        } else if request_path == "/api/accounts/profile" {
            patch_profile_response(&resp_body, key_connector_url, org_name, org_id)
        } else if request_path == "/api/sync" {
            patch_sync_response(&resp_body, key_connector_url, org_name, org_id)
        } else if request_path.starts_with("/api/organizations/") && !request_path.contains("/users") && !request_path.contains("/domain/") {
            patch_org_response(&resp_body, key_connector_url)
        } else {
            resp_body.to_vec()
        }
    } else {
        resp_body.to_vec()
    };

    // Build the client response
    let mut response = HttpResponse::build(actix_web::http::StatusCode::from_u16(status.as_u16()).unwrap_or(actix_web::http::StatusCode::OK));

    for (key, value) in resp_headers.iter() {
        // Skip transfer-encoding/content-length since we may have changed the body
        let k = key.as_str().to_lowercase();
        if k == "transfer-encoding" || k == "content-length" || k == "content-security-policy" {
            continue;
        }
        if let Ok(v) = value.to_str() {
            // Use append_header for Set-Cookie to preserve multiple cookies
            // (e.g. VW admin panel login sends several Set-Cookie headers).
            // For all other headers, use insert_header (replace) to avoid
            // duplicate single-value headers confusing clients.
            if k == "set-cookie" {
                response.append_header((key.as_str(), v));
            } else {
                response.insert_header((key.as_str(), v));
            }
        }
    }

    response.body(final_body)
}

/// Handle POST /api/accounts/set-key-connector-key by forwarding to VW's
/// POST /api/accounts/keys (to store the user's asymmetric keys).
/// This endpoint doesn't exist in stock Vaultwarden, so the proxy translates it.
///
/// **IMPORTANT**: If the user already has a key enrolled, we skip storing new keys
/// and return the existing ones. The Bitwarden client generates a new key on every
/// SSO login — accepting it would overwrite the original encryption key and break
/// access to previously encrypted vault items.
async fn handle_set_key_connector_key(
    req: &HttpRequest,
    body: &web::Bytes,
    client: &Client,
    vw_url: &str,
    state: &web::Data<AppState>,
) -> HttpResponse {
    use crate::auth;

    // Authenticate to get the user ID
    let user = match auth::authenticate_request(req, &state.vw_decoding_key, &state.config).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!("set-key-connector-key: authentication failed: {e}");
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication failed"}));
        }
    };

    let json: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("set-key-connector-key: invalid JSON body: {e}");
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid JSON body"}));
        }
    };

    // Extract the keys and user key from the request body
    let keys = json.get("keys");
    let user_key = json.get("key");

    tracing::debug!(
        "set-key-connector-key: user={}, has_keys={}, has_user_key={}",
        user.user_id,
        keys.is_some(),
        user_key.is_some(),
    );

    // Check if user already has a key enrolled
    let existing_key: Option<serde_json::Value> = match state.db.get_user_key(&user.user_id) {
        Ok(Some(_record)) => {
            // User already has a key in masterless — still forward asymmetric keys to VW
            // (they may not be stored yet if this is the first enrollment attempt).
            // Then return 200 OK so the client proceeds with logIn() → GET /user-keys.
            tracing::info!("set-key-connector-key: user {} already has a key — forwarding asymmetric keys to VW and returning 200 OK", user.user_id);
            if let Some(keys_obj) = keys {
                let keys_url = format!("{vw_url}/api/accounts/keys");
                let mut keys_req = client.post(&keys_url);
                for (key, value) in req.headers() {
                    if key != "host" && key != "content-length" {
                        if let Ok(v) = value.to_str() {
                            keys_req = keys_req.header(key.as_str(), v);
                        }
                    }
                }
                keys_req = keys_req.json(keys_obj);
                match keys_req.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        tracing::info!("set-key-connector-key: stored asymmetric keys in VW (existing masterless key)");
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        tracing::info!("set-key-connector-key: VW POST /api/accounts/keys returned {status} (may already exist): {body}");
                        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
                            return HttpResponse::build(
                                actix_web::http::StatusCode::from_u16(status.as_u16())
                                    .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY)
                            ).json(serde_json::json!({"error": "Upstream rejected keys request"}));
                        }
                    }
                    Err(e) => {
                        tracing::error!("set-key-connector-key: failed to forward keys to VW: {e}");
                        return HttpResponse::BadGateway().json(serde_json::json!({"error": "Failed to store keys"}));
                    }
                }
            }
            if let Some(uk_enc_val) = user_key {
                if let Some(uk_enc_str) = uk_enc_val.as_str() {
                    match state.db.set_user_encrypted_key_if_absent(&user.user_id, uk_enc_str) {
                        Ok(stored) => tracing::info!(
                            "set-key-connector-key: UK_enc for user {} (existing K path) — stored={}",
                            user.user_id, stored
                        ),
                        Err(e) => tracing::warn!(
                            "set-key-connector-key: failed to store UK_enc for user {} (existing K path): {e}",
                            user.user_id
                        ),
                    }
                }
            }

            // Return the existing key (overwrite protection)
            match state.crypto.unseal_vault_key(&_record.encrypted_key) {
                Ok(decrypted_key) => {
                    tracing::info!("set-key-connector-key: user {} already has a key — returning existing key", user.user_id);
                    return HttpResponse::Ok().json(serde_json::json!({
                        "Object": "keyConnectorResponse",
                        "Key": decrypted_key
                    }));
                }
                Err(e) => {
                    tracing::error!("set-key-connector-key: failed to decrypt existing key for user {}: {}", user.user_id, e);
                    return HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to decrypt existing key (possible corruption or migration error)",
                        "details": format!("{}", e)
                    }));
                }
            }
        }
        Ok(None) => {
            tracing::info!("set-key-connector-key: user {} has no existing key — storing new keys", user.user_id);
            None
        }
        Err(e) => {
            tracing::warn!("set-key-connector-key: failed to check existing key for user {}: {}", user.user_id, e);
            None
        }
    };

    // If neither keys nor key is provided, reject the request
    if keys.is_none() && user_key.is_none() {
        tracing::warn!("set-key-connector-key: request body has neither keys nor key field");
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "No keys or key provided"}));
    }

    // If we couldn't retrieve an existing key, proceed with storing new keys
    if existing_key.is_none() {
        // Forward the user's asymmetric keys to VW via POST /api/accounts/keys
        if let Some(keys_obj) = keys {
            let keys_url = format!("{vw_url}/api/accounts/keys");
            let mut keys_req = client.post(&keys_url);
            // Forward auth headers
            for (key, value) in req.headers() {
                if key != "host" && key != "content-length" {
                    if let Ok(v) = value.to_str() {
                        keys_req = keys_req.header(key.as_str(), v);
                    }
                }
            }
            keys_req = keys_req.json(keys_obj);
            match keys_req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!("set-key-connector-key: stored asymmetric keys in VW");
                }
                Ok(resp) => {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    tracing::warn!("set-key-connector-key: VW POST /api/accounts/keys returned {status}: {body}");
                    // Propagate auth failures — other 4xx (e.g. "keys already exist") are expected
                    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
                        return HttpResponse::build(
                            actix_web::http::StatusCode::from_u16(status.as_u16())
                                .unwrap_or(actix_web::http::StatusCode::BAD_GATEWAY)
                        ).json(serde_json::json!({"error": "Upstream rejected keys request"}));
                    }
                }
                Err(e) => {
                    tracing::error!("set-key-connector-key: failed to forward keys to VW: {e}");
                    return HttpResponse::BadGateway().json(serde_json::json!({"error": "Failed to store keys"}));
                }
            }
        }

        if let Some(uk_enc_val) = user_key {
            if let Some(uk_enc_str) = uk_enc_val.as_str() {
                match state.db.set_user_encrypted_key_if_absent(&user.user_id, uk_enc_str) {
                    Ok(stored) => tracing::info!(
                        "set-key-connector-key: UK_enc for user {} — stored={}",
                        user.user_id, stored
                    ),
                    Err(e) => tracing::warn!(
                        "set-key-connector-key: failed to store UK_enc for user {}: {e}",
                        user.user_id
                    ),
                }
            }
            tracing::info!("set-key-connector-key: storing symmetric user key in masterless");
            return handle_set_user_key(req, body, state).await;
        }
    }

    // Return success — the web vault will proceed with the SSO flow
    HttpResponse::Ok().finish()
}

/// Handle POST /api/accounts/key — stores the wrapped symmetric user key.
///
/// The Bitwarden Server implements this endpoint to persist the user's
/// vault encryption key (wrapped/encrypted with the user's public key).
/// Stock Vaultwarden doesn't implement it, so we store it in masterless's
/// key store instead.
async fn handle_set_user_key(
    req: &HttpRequest,
    body: &web::Bytes,
    state: &web::Data<AppState>,
) -> HttpResponse {
    use crate::auth;

    // Authenticate the request using the JWT from the Authorization header
    let user = match auth::authenticate_request(req, &state.vw_decoding_key, &state.config).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!("set-user-key: authentication failed: {e}");
            return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Authentication failed"}));
        }
    };

    // Parse the request body to extract the key
    let json: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("set-user-key: invalid JSON body: {e}");
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid JSON body"}));
        }
    };

    // The key can be in "key" or "Key" field (camelCase or PascalCase)
    let key_value = json.get("key").or_else(|| json.get("Key"));

    // Check if user already has a key enrolled — if so, return it instead of overwriting
    if let Some(record) = state.db.get_user_key(&user.user_id).ok().flatten() {
        match state.crypto.unseal_vault_key(&record.encrypted_key) {
            Ok(decrypted_key) => {
                tracing::info!("set-user-key: user {} already has a key — returning existing key (preventing overwrite)", user.user_id);
                let response = serde_json::json!({
                    "Object": "keyConnectorResponse",
                    "Key": decrypted_key
                });
                return HttpResponse::Ok().json(response);
            }
            Err(e) => {
                tracing::error!("set-user-key: failed to decrypt existing key for user {}: {} (rejecting request, possible key corruption)", user.user_id, e);
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to decrypt existing key (possible corruption or migration error)",
                    "details": format!("{}", e)
                }));
            }
        }
    }

    tracing::info!(
        "set-user-key: user={}, key_field_present={}, body_keys={:?}",
        user.user_id,
        key_value.is_some(),
        json.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );

    let key_str = match key_value {
        Some(k) => match k.as_str() {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("set-user-key: key field is not a string");
                return HttpResponse::BadRequest().json(serde_json::json!({"error": "Key must be a string"}));
            }
        },
        None => {
            tracing::error!("set-user-key: no key field in request body");
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Missing key field"}));
        }
    };

    // Encrypt and store the key using our key manager
    match state.crypto.seal_vault_key(&key_str) {
        Ok(encrypted) => {
            // Store in our database — use upsert semantics since the client
            // may call this endpoint multiple times (e.g. on re-enrollment)
            if let Err(e) = state.db.insert_user_key(&user.user_id, &encrypted) {
                // If insert fails (duplicate key), try update instead
                tracing::warn!(
                    "set-user-key: insert failed for user {}, attempting update: {e}",
                    user.user_id
                );
                if let Err(e) = state.db.update_user_key(&user.user_id, &encrypted) {
                    tracing::error!("set-user-key: both insert and update failed: {e}");
                    return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to store key"}));
                }
                tracing::info!("set-user-key: updated symmetric key for user {}", user.user_id);
            } else {
                tracing::info!("set-user-key: successfully stored symmetric key for user {}", user.user_id);
            }
            HttpResponse::Ok().finish()
        }
        Err(e) => {
            tracing::error!("set-user-key: encryption failed: {e}");
            HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to encrypt key"}))
        }
    }
}

fn extract_user_id_from_login_response(body: &[u8]) -> Option<uuid::Uuid> {
    let json: Value = serde_json::from_slice(body).ok()?;
    let token = json.get("access_token")?.as_str()?;
    let payload_b64 = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    let sub = claims.get("sub")?.as_str()?;
    uuid::Uuid::parse_str(sub).ok()
}

/// What the client is asking for at `/identity/connect/token`.
///
/// `password` means the session really does have a master password, and the passwordless
/// treatment must not be applied to it: answering `HasMasterPassword: false` plus a
/// KeyConnectorOption would tell the client to skip the password the account has and offer a
/// connector flow that user never enrolled in. Everything else — `authorization_code` (the
/// SSO callback) and `refresh_token` — keeps the configured behaviour.
///
/// The grant type is read from the request the client just sent, which is the one signal
/// that exists on every Vaultwarden build; nothing else in the response distinguishes an SSO
/// session from a password one.
fn request_grant_type(body: &[u8]) -> Option<String> {
    if let Ok(json) = serde_json::from_slice::<Value>(body) {
        if let Some(grant) = json.get("grant_type").and_then(Value::as_str) {
            return Some(grant.to_ascii_lowercase());
        }
    }
    // Fall back to a form-encoded body for older clients.
    let text = std::str::from_utf8(body).ok()?;
    for pair in text.split('&') {
        if let Some(value) = pair.strip_prefix("grant_type=") {
            return Some(value.to_ascii_lowercase());
        }
    }
    None
}

fn patch_login_response(body: &[u8], key_connector_url: &str, user_has_key: bool, user_encrypted_key: Option<&str>) -> Vec<u8> {
    let mut json: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.to_vec(),
    };

    if user_has_key {
        if let Some(uk_enc) = user_encrypted_key {
            json["Key"] = serde_json::json!(uk_enc);
        }
    }

    // Vaultwarden only sends UserDecryptionOptions in the *login* response: a refresh token
    // grant replies without it. A client that comes back on a refreshed session (which is
    // what every mobile app does when it is reopened) then has no way to learn that it should
    // unlock through the connector and falls back to the login screen — the "log in again on
    // every restart" symptom. Create the object when the server omits it.
    if json.get("UserDecryptionOptions").is_none() {
        json["UserDecryptionOptions"] = serde_json::json!({});
    }

    if let Some(opts) = json.get_mut("UserDecryptionOptions") {
        // If the server already answers with a connector, its URL is authoritative: pointing
        // the client at a different one silently would split the deployment in two.
        if opts.get("KeyConnectorOption").is_some() {
            tracing::debug!("login-response patch: server already advertises a KeyConnectorOption — leaving it");
        } else {
            opts["HasMasterPassword"] = serde_json::json!(false);
            opts["KeyConnectorOption"] = serde_json::json!({
                "KeyConnectorUrl": key_connector_url,
                "Object": "keyConnectorUserDecryptionOption"
            });
        }
    }

    serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec())
}


/// Patch the /api/accounts/profile response
fn patch_profile_response(body: &[u8], key_connector_url: &str, org_name: &str, org_identifier: &str) -> Vec<u8> {
    let mut json: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.to_vec(),
    };

        json["usesKeyConnector"] = Value::Bool(true);

    if !json.get("organizations").is_some_and(|v| v.is_array()) {
        json["organizations"] = Value::Array(vec![]);
    }
    
    if let Some(orgs) = json.get_mut("organizations") {
        patch_org_array(orgs, key_connector_url, org_name, org_identifier);
    }

    serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec())
}

/// Patch the /api/sync response
fn patch_sync_response(body: &[u8], key_connector_url: &str, org_name: &str, org_identifier: &str) -> Vec<u8> {
    let mut json: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.to_vec(),
    };

    if !json.get("profile").is_some_and(|v| v.is_object()) {
        json["profile"] = serde_json::json!({});
    }
    let profile = match json.get_mut("profile") {
        Some(v) => v,
        None => {
            tracing::warn!("profile missing after insertion in sync response");
            return body.to_vec();
        }
    };
    profile["usesKeyConnector"] = Value::Bool(true);

    if !profile.get("organizations").is_some_and(|v| v.is_array()) {
        profile["organizations"] = Value::Array(vec![]);
    }
    if let Some(orgs) = profile.get_mut("organizations") {
        patch_org_array(orgs, key_connector_url, org_name, org_identifier);
    }

    if !json.get("userDecryption").is_some_and(|v| v.is_object()) {
        json["userDecryption"] = serde_json::json!({});
    }
    let ud = match json.get_mut("userDecryption") {
        Some(v) => v,
        None => {
            tracing::warn!("userDecryption missing after insertion in sync response");
            return body.to_vec();
        }
    };
    ud["keyConnectorUnlock"] = serde_json::json!({
        "keyConnectorUrl": key_connector_url
    });

    serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec())
}

/// Patch a single organization JSON response
fn patch_org_response(body: &[u8], key_connector_url: &str) -> Vec<u8> {
    let mut json: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.to_vec(),
    };

    patch_single_org(&mut json, key_connector_url);

    serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec())
}

/// Inject passwordless flags into an array of organization objects.
///
/// The Key Connector enrollment and unlock flows are driven by:
/// - KeyConnectorOption in the login token response
/// - keyConnectorUnlock in the sync userDecryption object
///
/// Neither depends on findManagingOrganization(), so we no longer inject
/// a synthetic organization. This avoids the Bitwarden WASM client crash
/// where decapsulateKeyUnsigned is called on a null org key.
fn patch_org_array(orgs: &mut Value, key_connector_url: &str, _org_name: &str, _org_identifier: &str) {
    if let Some(arr) = orgs.as_array_mut() {
        for org in arr.iter_mut() {
            patch_single_org(org, key_connector_url);
        }
    }
}

/// Inject passwordless flags into a single organization object
fn patch_single_org(org: &mut Value, key_connector_url: &str) {
    org["useKeyConnector"] = Value::Bool(true);
    org["keyConnectorEnabled"] = Value::Bool(true);
    org["keyConnectorUrl"] = Value::String(key_connector_url.to_string());
    org["usesKeyConnector"] = Value::Bool(true);
}

/// Log the client version info from a token request body for compatibility monitoring.
/// Extracts `device-type`, `device-name`, and `device-identifier` if present.
// ---- what the client tells us about itself -------------------------------------------------

/// Fields a client sends on `POST /identity/connect/token`. Bitwarden clients post JSON; the
/// mobile apps post form-encoded (JSON answers 415 and they retry), so parse both — otherwise
/// every phone is invisible in the logs and the diagnostics below never fire.
#[derive(Debug, Default, PartialEq)]
pub struct TokenRequestInfo {
    pub device_type: String,
    pub device_name: String,
    pub device_id: String,
    pub grant_type: String,
}

/// Percent-decode `application/x-www-form-urlencoded` text (`+` means a space).
fn form_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn fields_from_body(body: &[u8]) -> HashMap<String, String> {
    if let Ok(json) = serde_json::from_slice::<Value>(body) {
        if let Some(obj) = json.as_object() {
            // The clients send numbers where a string is expected (`"deviceType": 0`), so keep
            // those too — dropping them is what made phones invisible in the first place.
            return obj
                .iter()
                .filter_map(|(k, v)| match v {
                    Value::String(s) => Some((k.clone(), s.clone())),
                    Value::Number(n) => Some((k.clone(), n.to_string())),
                    _ => None,
                })
                .collect();
        }
    }
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (form_decode(k), form_decode(v)))
        .collect()
}

fn pick(fields: &HashMap<String, String>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|k| fields.get(*k))
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
}

/// Extract the client identity from a token request body, whichever shape it arrives in.
pub fn parse_token_request(body: &[u8]) -> TokenRequestInfo {
    let fields = fields_from_body(body);
    TokenRequestInfo {
        device_type: pick(&fields, &["deviceType", "device_type"]),
        device_name: pick(&fields, &["deviceName", "device_name"]),
        device_id: pick(&fields, &["deviceIdentifier", "device_identifier"]),
        grant_type: pick(&fields, &["grantType", "grant_type"]),
    }
}

/// Bitwarden's mobile `DeviceType` values are 0 (Android), 1 (iOS) and 15 (AndroidAmazon);
/// some clients send the spelled-out form instead.
pub fn is_mobile_device(device_type: &str) -> bool {
    if matches!(device_type.trim(), "0" | "1" | "15") {
        return true;
    }
    let t = device_type.to_lowercase();
    t.contains("mobile") || t.contains("android") || t.contains("ios")
}

/// A client that cannot unlock — a Key Connector account with no master password and no
/// PIN/biometrics — is deliberately logged out by the app and comes back with a fresh login,
/// over and over. Counting authentication attempts per device turns that into one explained
/// warning instead of an unexplained flood.
const LOGIN_LOOP_THRESHOLD: u32 = 5;
const LOGIN_LOOP_WINDOW: Duration = Duration::from_secs(15 * 60);

static LOGIN_ATTEMPTS: LazyLock<Mutex<HashMap<String, (u32, Instant)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The window arithmetic, kept pure so it can be tested without the process-wide map.
fn advance_attempt_window(state: (u32, Instant), now: Instant) -> (u32, Instant) {
    if now.duration_since(state.1) > LOGIN_LOOP_WINDOW {
        (1, now)
    } else {
        (state.0 + 1, state.1)
    }
}

/// Records one authentication attempt; returns the count when it first crosses the threshold
/// inside a window. Refreshes are not attempts — a healthy client refreshes all day.
fn note_login_attempt(device_id: &str, now: Instant) -> Option<u32> {
    let mut attempts = LOGIN_ATTEMPTS.lock().ok()?;
    let entry = attempts
        .entry(device_id.to_string())
        .or_insert((0, now))
        .clone();
    let updated = advance_attempt_window(entry, now);
    *attempts
        .get_mut(device_id)
        .expect("entry was just inserted") = updated;
    (updated.0 == LOGIN_LOOP_THRESHOLD).then_some(updated.0)
}

fn track_client_version(state: &web::Data<crate::api::AppState>, body: &[u8]) {
    let info = parse_token_request(body);

    tracing::info!(
        "Client connected: type={}, name={}, id={}, grant={}",
        info.device_type,
        info.device_name,
        &info.device_id[..info.device_id.len().min(8)],
        info.grant_type
    );

    if is_mobile_device(&info.device_type)
        && state.config.compat_clients.contains("\"mobile\":\"untested\"")
    {
        tracing::warn!(
            "Mobile client connected but mobile compatibility is untested! See COMPATIBILITY.md \
             for tested versions. Last tested: {}",
            state.config.compat_last_tested
        );
    }

    let authenticating = !info.grant_type.eq_ignore_ascii_case("refresh_token");
    if authenticating && info.device_id != "unknown" {
        if let Some(attempts) = note_login_attempt(&info.device_id, Instant::now()) {
            tracing::warn!(
                "Device {} ({}) authenticated {} times in {} minutes. On a passwordless \
                 (Key Connector) account this is the signature of a client with no unlock \
                 mechanism: the app logs itself out instead of unlocking, so the user has to log \
                 in again on every visit. Have them enable 'Unlock with PIN code' or biometrics \
                 in the app — see COMPATIBILITY.md.",
                &info.device_id[..info.device_id.len().min(8)],
                info.device_name,
                attempts,
                LOGIN_LOOP_WINDOW.as_secs() / 60
            );
        }
    }
}


/// Handle WebSocket upgrade: create a bidirectional tunnel between client and upstream Vaultwarden.
/// This enables SignalR notifications (/notifications/hub) for live sync in the web vault.
async fn handle_websocket_proxy(
    req: HttpRequest,
    body: web::Payload,
    vw_url: &str,
    path: &str,
) -> HttpResponse {
    use futures_util::StreamExt as _;
    use futures_util::SinkExt;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message as WsMsg;

    // Build upstream WebSocket URL
    let upstream_url = if vw_url.starts_with("https://") {
        format!("wss://{}{}", &vw_url[8..], path)
    } else if vw_url.starts_with("http://") {
        format!("ws://{}{}", &vw_url[7..], path)
    } else {
        format!("ws://{}{}", vw_url, path)
    };

    // Accept the client WebSocket — this performs the HTTP upgrade and returns
    // the 101 response immediately. We must return this response BEFORE starting
    // the relay loop, otherwise the client never receives the upgrade confirmation.
    let (response, mut session, mut client_stream) = match actix_ws::handle(&req, body) {
        Ok(parts) => parts,
        Err(e) => {
            tracing::error!("WebSocket proxy: failed to accept client: {e}");
            return HttpResponse::BadRequest().finish();
        }
    };

    tracing::info!("WebSocket proxy: opening tunnel to {upstream_url}");

    // Connect to upstream Vaultwarden via WebSocket
    let (upstream, _resp) = match connect_async(&upstream_url).await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("WebSocket proxy: upstream connection failed: {e}");
            let _ = session.close(None).await;
            return response;
        }
    };

    // Spawn the bidirectional relay in a background task.
    // This is critical: the 101 response MUST be returned to the client first.
    actix_rt::spawn(async move {
        let (mut upstream_write, mut upstream_read) = upstream.split();

        loop {
            tokio::select! {
                msg = client_stream.next() => {
                    match msg {
                        Some(Ok(actix_ws::Message::Ping(bytes))) => {
                            if upstream_write.send(WsMsg::Ping(bytes.to_vec())).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(actix_ws::Message::Text(text))) => {
                            if upstream_write.send(WsMsg::Text(text.to_string())).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(actix_ws::Message::Binary(bin))) => {
                            if upstream_write.send(WsMsg::Binary(bin.to_vec())).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(actix_ws::Message::Close(reason))) => {
                            let _ = upstream_write.send(WsMsg::Close(None)).await;
                            let _ = session.close(reason).await;
                            return;
                        }
                        Some(Err(e)) => {
                            tracing::warn!("WebSocket proxy: client error: {e}");
                            break;
                        }
                        None => break,
                        _ => continue,
                    }
                }
                msg = upstream_read.next() => {
                    match msg {
                        Some(Ok(WsMsg::Text(text))) => {
                            if session.text(text).await.is_err() { break; }
                        }
                        Some(Ok(WsMsg::Binary(bin))) => {
                            if session.binary(bin).await.is_err() { break; }
                        }
                        Some(Ok(WsMsg::Ping(data))) => {
                            if session.ping(&data).await.is_err() { break; }
                        }
                        Some(Ok(WsMsg::Pong(_))) => continue,
                        Some(Ok(WsMsg::Close(_))) => {
                            let _ = session.close(None).await;
                            return;
                        }
                        Some(Err(e)) => {
                            tracing::warn!("WebSocket proxy: upstream error: {e}");
                            break;
                        }
                        None => break,
                        _ => continue,
                    }
                }
            }
        }
        let _ = session.close(None).await;
    });

    // Return the 101 Switching Protocols response immediately
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_form_encoded_token_request() {
        // what the mobile apps send on the retry after their JSON attempt gets a 415
        let body = b"grant_type=authorization_code&deviceType=0&deviceName=moto+g54+5G&deviceIdentifier=abc123";
        let info = parse_token_request(body);
        assert_eq!(info.grant_type, "authorization_code");
        assert_eq!(info.device_type, "0");
        assert_eq!(info.device_name, "moto g54 5G");
        assert_eq!(info.device_id, "abc123");
    }

    #[test]
    fn parses_a_json_token_request() {
        let body = br#"{"grantType":"refresh_token","deviceType":10,"deviceName":"firefox","deviceIdentifier":"zzz"}"#;
        let info = parse_token_request(body);
        assert_eq!(info.grant_type, "refresh_token");
        assert_eq!(info.device_type, "10");
        assert_eq!(info.device_name, "firefox");
        assert_eq!(info.device_id, "zzz");
    }

    #[test]
    fn missing_fields_are_reported_as_unknown_not_dropped() {
        let info = parse_token_request(b"");
        assert_eq!(info.device_id, "unknown");
        assert_eq!(info.grant_type, "unknown");
    }

    #[test]
    fn recognises_the_mobile_device_types_the_clients_send() {
        for mobile in ["0", "1", "15", "Android", "iOS", "mobile"] {
            assert!(is_mobile_device(mobile), "{mobile} should count as mobile");
        }
        for other in ["2", "8", "10", "21", "SDK", "linux"] {
            assert!(!is_mobile_device(other), "{other} should not count as mobile");
        }
    }

    #[test]
    fn counts_attempts_inside_a_window_and_starts_over_after_it() {
        let t0 = Instant::now();
        let mut state = (0, t0);
        for _ in 0..3 {
            state = advance_attempt_window(state, t0);
        }
        assert_eq!(state.0, 3);

        let later = t0 + LOGIN_LOOP_WINDOW + Duration::from_secs(1);
        state = advance_attempt_window(state, later);
        assert_eq!(state.0, 1, "a new window counts from one again");
    }

    const TEST_ORG_NAME: &str = "Vaultwarden Masterless";
    const TEST_ORG_IDENTIFIER: &str = "vaultwarden-masterless";

    /// Simulate the key_connector_url derivation from USER_KEYS_URL.
    /// In production this happens in proxy_handler; tests call patch functions directly.
    fn derive_key_connector_url(user_keys_url: &str) -> &str {
        user_keys_url
            .trim_end_matches('/')
            .strip_suffix("/user-keys")
            .unwrap_or(user_keys_url)
    }

    #[test]
    fn test_request_grant_type_detection() {
        // JSON bodies (what the clients send today)
        assert_eq!(
            request_grant_type(br#"{"grant_type":"password","username":"a@b.c"}"#),
            Some("password".to_string())
        );
        assert_eq!(
            request_grant_type(br#"{"grant_type":"authorization_code","code":"x"}"#),
            Some("authorization_code".to_string())
        );
        assert_eq!(
            request_grant_type(br#"{"grant_type":"refresh_token"}"#),
            Some("refresh_token".to_string())
        );
        // Form-encoded, for older clients
        assert_eq!(
            request_grant_type(b"grant_type=password&username=a%40b.c"),
            Some("password".to_string())
        );
        // Unknown/absent: leave the decision to the caller (previous behaviour)
        assert_eq!(request_grant_type(b"{}"), None);
        assert_eq!(request_grant_type(b"not json at all"), None);
    }

    #[test]
    fn test_patch_login_response_keeps_a_connector_the_server_already_advertises() {
        let input = serde_json::json!({
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "KeyConnectorOption": {
                    "KeyConnectorUrl": "https://server-side.example.com",
                    "Object": "keyConnectorUserDecryptionOption"
                }
            }
        });
        let patched = patch_login_response(
            serde_json::to_vec(&input).unwrap().as_slice(),
            "https://ours.example.com",
            false,
            None,
        );
        let out: Value = serde_json::from_slice(&patched).unwrap();
        assert_eq!(
            out["UserDecryptionOptions"]["KeyConnectorOption"]["KeyConnectorUrl"],
            "https://server-side.example.com",
            "the server's own connector must win"
        );
        assert_eq!(out["UserDecryptionOptions"]["HasMasterPassword"], true);
    }

    #[test]
    fn test_key_connector_url_derivation() {
        // Standard case: full /user-keys URL → base URL
        assert_eq!(
            derive_key_connector_url("https://vault.example.com/user-keys"),
            "https://vault.example.com"
        );
        // Trailing slash
        assert_eq!(
            derive_key_connector_url("https://vault.example.com/user-keys/"),
            "https://vault.example.com"
        );
        // With subpath
        assert_eq!(
            derive_key_connector_url("https://example.com/vault/user-keys"),
            "https://example.com/vault"
        );
        // Already a base URL (no /user-keys suffix) — should pass through unchanged
        assert_eq!(
            derive_key_connector_url("https://vault.example.com"),
            "https://vault.example.com"
        );
        // Internal URL
        assert_eq!(
            derive_key_connector_url("http://localhost:8484/user-keys"),
            "http://localhost:8484"
        );
    }

    #[test]
    fn test_patch_login_response() {
        let input = serde_json::json!({
            "access_token": "fake",
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "Object": "userDecryptionOptions"
            }
        });
        let body = serde_json::to_vec(&input).unwrap();
        let patched = patch_login_response(&body, "https://vault.example.com", false, None);
        let result: Value = serde_json::from_slice(&patched).unwrap();

        assert_eq!(
            result["UserDecryptionOptions"]["KeyConnectorOption"]["KeyConnectorUrl"],
            "https://vault.example.com"
        );
        assert_eq!(
            result["UserDecryptionOptions"]["HasMasterPassword"],
            false
        );
        assert!(result["Key"].is_null(), "Key must not be injected for new users");

        let uk_enc = "2.abc123==|def456==|ghi789==";
        let patched_enrolled = patch_login_response(&body, "https://vault.example.com", true, Some(uk_enc));
        let result_enrolled: Value = serde_json::from_slice(&patched_enrolled).unwrap();
        assert_eq!(
            result_enrolled["Key"],
            uk_enc,
            "UK_enc must be injected as Key field for returning users"
        );
        assert_eq!(
            result_enrolled["UserDecryptionOptions"]["KeyConnectorOption"]["KeyConnectorUrl"],
            "https://vault.example.com",
            "KeyConnectorOption must be present for returning users so client calls GET /user-keys"
        );
        assert!(result_enrolled["UserDecryptionOptions"]["keyConnectorUnlock"].is_null(),
            "keyConnectorUnlock must not be set — client uses Key field + KeyConnectorOption instead");
    }

    #[test]
    fn test_patch_profile_response() {
        let input = serde_json::json!({
            "id": "user-1",
            "usesKeyConnector": false,
            "organizations": [
                {
                    "id": "org-1",
                    "useKeyConnector": false,
                    "keyConnectorEnabled": false,
                    "keyConnectorUrl": null
                }
            ]
        });
        let body = serde_json::to_vec(&input).unwrap();
        let patched = patch_profile_response(&body, "https://vault.example.com", TEST_ORG_NAME, TEST_ORG_IDENTIFIER);
        let result: Value = serde_json::from_slice(&patched).unwrap();

        assert_eq!(result["usesKeyConnector"], true);
        assert_eq!(result["organizations"][0]["useKeyConnector"], true);
        assert_eq!(result["organizations"][0]["keyConnectorEnabled"], true);
        assert_eq!(result["organizations"][0]["keyConnectorUrl"], "https://vault.example.com");
    }

    #[test]
    fn test_patch_sync_response() {
        let input = serde_json::json!({
            "profile": {
                "id": "user-1",
                "usesKeyConnector": false,
                "organizations": [
                    {
                        "id": "org-1",
                        "useKeyConnector": false,
                        "keyConnectorEnabled": false,
                        "keyConnectorUrl": null
                    }
                ]
            },
            "userDecryption": {
                "masterPasswordUnlock": null
            },
            "ciphers": []
        });
        let body = serde_json::to_vec(&input).unwrap();
        let patched = patch_sync_response(&body, "https://vault.example.com", TEST_ORG_NAME, TEST_ORG_IDENTIFIER);
        let result: Value = serde_json::from_slice(&patched).unwrap();

        assert_eq!(result["profile"]["usesKeyConnector"], true);
        assert_eq!(result["profile"]["organizations"][0]["keyConnectorEnabled"], true);
        assert_eq!(result["userDecryption"]["keyConnectorUnlock"]["keyConnectorUrl"], "https://vault.example.com");
    }

    #[test]
    fn test_patch_org_response() {
        let input = serde_json::json!({
            "id": "org-1",
            "name": "Test Org",
            "useKeyConnector": false,
            "keyConnectorEnabled": false,
            "keyConnectorUrl": null
        });
        let body = serde_json::to_vec(&input).unwrap();
        let patched = patch_org_response(&body, "https://vault.example.com");
        let result: Value = serde_json::from_slice(&patched).unwrap();

        assert_eq!(result["useKeyConnector"], true);
        assert_eq!(result["keyConnectorEnabled"], true);
        assert_eq!(result["keyConnectorUrl"], "https://vault.example.com");
    }

    #[test]
    fn test_patch_non_json_passthrough() {
        let body = b"not json at all";
        let result = patch_login_response(body, "https://vault.example.com", false, None);
        assert_eq!(result, body);
    }

    #[test]
    fn test_login_response_no_uk_enc_does_not_inject_key() {
        // Reproducing test: When proxy_handler incorrectly passes the MASTER KEY
        // as user_encrypted_key (instead of UK_enc), patch_login_response would
        // inject the wrong value in the "Key" field.
        //
        // This test verifies the CONTRACT:
        // - When user_encrypted_key is None, Key field MUST NOT be injected
        //   (even when user_has_key is true — that's a data-gathering bug, not
        //    the patch function's responsibility)
        // - The proxy_handler MUST NOT pass the master key as user_encrypted_key
        let input = serde_json::json!({
            "access_token": "fake",
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "Object": "userDecryptionOptions"
            }
        });
        let body = serde_json::to_vec(&input).unwrap();

        // Scenario 1: user_has_key=false, no uk_enc → Key field absent
        let patched_no_key = patch_login_response(&body, "https://vault.example.com", false, None);
        let result_no_key: Value = serde_json::from_slice(&patched_no_key).unwrap();
        assert!(
            result_no_key.get("Key").is_none() || result_no_key["Key"].is_null(),
            "Key must NOT be injected when user_has_key=false and no uk_enc"
        );

        // Scenario 2: user_has_key=true, uk_enc=None → Key field absent
        // This simulates the correct behavior when UK_enc is missing from app_data.
        // The proxy_handler should NOT fall back to the master key.
        let patched_missing = patch_login_response(&body, "https://vault.example.com", true, None);
        let result_missing: Value = serde_json::from_slice(&patched_missing).unwrap();
        assert!(
            result_missing.get("Key").is_none() || result_missing["Key"].is_null(),
            "Key must NOT be injected when uk_enc is None, even if user_has_key=true"
        );

        // Scenario 3: user_has_key=true, uk_enc=Some(value) → Key field MUST be injected
        let uk_enc = "2.abc123==|def456==|ghi789==";
        let patched_with = patch_login_response(&body, "https://vault.example.com", true, Some(uk_enc));
        let result_with: Value = serde_json::from_slice(&patched_with).unwrap();
        assert_eq!(
            result_with["Key"], uk_enc,
            "Key field must contain UK_enc when user_has_key=true and uk_enc is Some"
        );
    }

    #[test]
    fn test_uk_enc_backfill_removed() {
        // Verifies the backfill removal fix: patch_login_response must NOT inject
        // the Key field when uk_enc is None, even if user_has_key=true.
        let input = serde_json::json!({
            "access_token": "fake",
            "UserDecryptionOptions": {
                "HasMasterPassword": true,
                "Object": "userDecryptionOptions"
            }
        });
        let body = serde_json::to_vec(&input).unwrap();
        let kc_url = "https://vault.example.com";

        // Scenario A: user_has_key=true, uk_enc=None → Key MUST NOT be injected
        let result_a = patch_login_response(&body, kc_url, true, None);
        let json_a: Value = serde_json::from_slice(&result_a).unwrap();
        assert!(
            json_a.get("Key").is_none() || json_a["Key"].is_null(),
            "Scenario A: Key must NOT be injected when uk_enc is None, even if user_has_key=true"
        );

        // Scenario B: user_has_key=true, uk_enc=Some(...) → Key MUST contain UK_enc
        let uk_enc = "2.abc123==|def456==|ghi789==";
        let result_b = patch_login_response(&body, kc_url, true, Some(uk_enc));
        let json_b: Value = serde_json::from_slice(&result_b).unwrap();
        assert_eq!(
            json_b["Key"], uk_enc,
            "Scenario B: Key field must contain UK_enc when uk_enc is provided"
        );
        assert_eq!(
            json_b["UserDecryptionOptions"]["KeyConnectorOption"]["KeyConnectorUrl"],
            kc_url,
            "KeyConnectorOption must be present in all scenarios"
        );

        // Scenario C: user_has_key=false, uk_enc=None → Key MUST NOT be injected
        let result_c = patch_login_response(&body, kc_url, false, None);
        let json_c: Value = serde_json::from_slice(&result_c).unwrap();
        assert!(
            json_c.get("Key").is_none() || json_c["Key"].is_null(),
            "Scenario C: Key must NOT be injected when user_has_key=false"
        );
    }

    #[test]
    fn test_empty_orgs_remain_empty() {
        let input = serde_json::json!({
            "id": "user-1",
            "usesKeyConnector": false,
            "organizations": []
        });
        let body = serde_json::to_vec(&input).unwrap();
        let patched = patch_profile_response(&body, "https://vault.example.com", TEST_ORG_NAME, TEST_ORG_IDENTIFIER);
        let result: Value = serde_json::from_slice(&patched).unwrap();

        assert_eq!(result["usesKeyConnector"], true);
        let orgs = result["organizations"].as_array().unwrap();
        assert_eq!(orgs.len(), 0, "Should NOT inject synthetic org - organizations remain empty");
    }

    #[test]
    fn test_empty_orgs_remain_empty_in_sync() {
        let input = serde_json::json!({
            "profile": {
                "id": "user-1",
                "usesKeyConnector": false,
                "organizations": []
            },
            "userDecryption": {
                "masterPasswordUnlock": null
            },
            "ciphers": []
        });
        let body = serde_json::to_vec(&input).unwrap();
        let patched = patch_sync_response(&body, "https://vault.example.com", TEST_ORG_NAME, TEST_ORG_IDENTIFIER);
        let result: Value = serde_json::from_slice(&patched).unwrap();

        let orgs = result["profile"]["organizations"].as_array().unwrap();
        assert_eq!(orgs.len(), 0, "Should NOT inject synthetic org - organizations remain empty");
        // Verify keyConnectorUnlock is still injected for the unlock flow
        assert_eq!(result["userDecryption"]["keyConnectorUnlock"]["keyConnectorUrl"], "https://vault.example.com");
    }

    #[test]
    fn test_synthetic_org_not_injected_when_orgs_exist() {
        // When the user already has orgs, we patch them instead of injecting
        let input = serde_json::json!({
            "id": "user-1",
            "usesKeyConnector": false,
            "organizations": [
                {
                    "id": "real-org-1",
                    "name": "Real Org",
                    "useKeyConnector": false,
                    "keyConnectorEnabled": false,
                    "keyConnectorUrl": null
                }
            ]
        });
        let body = serde_json::to_vec(&input).unwrap();
        let patched = patch_profile_response(&body, "https://vault.example.com", TEST_ORG_NAME, TEST_ORG_IDENTIFIER);
        let result: Value = serde_json::from_slice(&patched).unwrap();

        let orgs = result["organizations"].as_array().unwrap();
        assert_eq!(orgs.len(), 1, "Should NOT inject — org already exists");
        assert_eq!(orgs[0]["id"], "real-org-1", "Should be the original org, not synthetic");
        assert_eq!(orgs[0]["keyConnectorEnabled"], true, "Existing org should be patched");
    }
}
