use actix_web::{test, web, App};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

// We reference the library crate
use vaultwarden_masterless::api::{self, AppState};
use vaultwarden_masterless::config::Config;
use vaultwarden_masterless::crypto::VaultKeyManager;
use vaultwarden_masterless::db::Database;
use vaultwarden_masterless::proxy;

/// JWT claims matching what Vaultwarden produces
#[derive(Serialize)]
struct TestClaims {
    sub: String,
    email: String,
    amr: Vec<String>,
    exp: u64,
    iss: String,
}

/// Helper: generate an RSA keypair and return (private_pem, public_pem, encoding_key, decoding_key)
fn test_keys() -> (String, String, EncodingKey, jsonwebtoken::DecodingKey) {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let public_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

    let enc = EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();
    let dec = jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap();

    (private_pem, public_pem, enc, dec)
}

/// Helper: create a signed JWT for a given user
fn make_jwt(enc_key: &EncodingKey, user_id: &Uuid, email: &str) -> String {
    let claims = TestClaims {
        sub: user_id.to_string(),
        email: email.to_string(),
        amr: vec!["Application".to_string()],
        exp: (chrono::Utc::now().timestamp() + 3600) as u64,
        iss: "https://vw.test.local|login".to_string(),
    };
    encode(&Header::new(Algorithm::RS256), &claims, enc_key).unwrap()
}

/// Helper: build the full test app with in-memory DB
fn build_app_state(
    vw_dec_key: jsonwebtoken::DecodingKey,
    app_private_pem: &str,
    app_public_pem: &str,
) -> web::Data<AppState> {
    let db = Database::open(":memory:").unwrap();
    let crypto = VaultKeyManager::new(app_private_pem, app_public_pem).unwrap();
    crypto.bootstrap_wrapping_key(&db).unwrap();

    let config = Config {
        host: "127.0.0.1".to_string(),
        port: 8484,
        vaultwarden_url: "https://vw.test.local".to_string(),
        vaultwarden_rsa_public_key_file: String::new(),
        database_path: ":memory:".to_string(),
        rsa_private_key_file: String::new(),
        rsa_public_key_file: String::new(),
        log_level: "debug".to_string(),
        proxy_enabled: false,
        user_keys_url: String::new(),
        rotation_interval_hours: 0,
        domain: None,
        tls_cert_file: None,
        tls_key_file: None,
        synthetic_org_name: "Vaultwarden Masterless".to_string(),
        synthetic_org_identifier: "vaultwarden-masterless".to_string(),
        build_sha: String::new(),
        compat_vw_version: "1.37.3".to_string(),
        compat_kc_version: "26.3.4".to_string(),
        compat_clients: r#"{"web":"2024.x - 2026.x","desktop":"2024.x - 2026.x","browser_extension":"2024.x - 2026.x","mobile":"untested"}"#.to_string(),
        compat_last_tested: "2026-09-18".to_string(),
        compat_status_url: "https://github.com/antoniolago/vaultwarden-masterless/blob/main/COMPATIBILITY.md".to_string(),
    };

    web::Data::new(AppState {
        db: Arc::new(db),
        crypto: Arc::new(crypto),
        config: Arc::new(config),
        vw_decoding_key: vw_dec_key,
        http_client: reqwest::Client::new(),
        sso_cookies: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        vw_version: tokio::sync::Mutex::new(None),
    })
}

// ============================================================================
// Integration Tests — /user-keys (api.rs routes)
// ============================================================================

#[actix_web::test]
async fn test_alive_endpoint() {
    let (_, _, _, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let req = test::TestRequest::get().uri("/alive").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["alive"], true);
    assert!(body["now"].is_string());
}

#[actix_web::test]
async fn test_version_reports_tested_and_detected_vaultwarden() {
    let (_, _, _, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    // Before/without a successful probe: version is reported as unreachable
    let req = test::TestRequest::get().uri("/version").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    assert!(resp
        .headers()
        .contains_key("X-Vaultwarden-Masterless-Version"));

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["alive"], true);
    assert_eq!(body["compatibility"]["vaultwarden"], "1.37.3");
    assert!(body["compatibility"]["vaultwarden_detected"].is_null());
    assert_eq!(body["compatibility"]["status"], "unreachable");
    assert!(body["compatibility"]["status_url"].is_string());

    // A detected version flips the verdict instead of passing silently
    *state.vw_version.lock().await = Some("1.37.4".to_string());
    let req = test::TestRequest::get().uri("/version").to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["compatibility"]["vaultwarden_detected"], "1.37.4");
    assert_eq!(body["compatibility"]["status"], "newer");
}

#[actix_web::test]
async fn test_get_without_auth_returns_401() {
    let (_, _, _, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let req = test::TestRequest::get().uri("/user-keys").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_get_with_invalid_token_returns_401() {
    let (_, _, _, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", "Bearer invalid.token.here"))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_get_nonexistent_key_returns_404() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "user@test.com");

    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_full_enrollment_flow() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "alice@test.com");
    let user_key = B64.encode(b"this-is-alice-encryption-key-for-vault");

    // Step 1: POST — enroll key
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({ "Key": &user_key }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "POST should succeed for new enrollment");

    // Step 2: GET — retrieve key
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "GET should succeed after enrollment");

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["Key"], user_key, "Retrieved key must match enrolled key");
}

#[actix_web::test]
async fn test_duplicate_enrollment_is_idempotent() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "bob@test.com");
    let user_key = B64.encode(b"bobs-key");

    // First POST — should succeed (new enrollment)
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &user_key }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // Seed UK_enc in app_data (simulates proxy storing it after enrollment flow)
    state.db.set_user_encrypted_key_if_absent(&user_id, "test_uk_enc").unwrap();

    // Second POST — idempotent: returns 200 with the existing key
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &user_key }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "Duplicate POST should be idempotent");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["Key"], user_key, "Should return the stored key");
}

#[actix_web::test]
async fn test_put_updates_key() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "carol@test.com");
    let key_v1 = B64.encode(b"carols-key-v1");
    let key_v2 = B64.encode(b"carols-key-v2-rotated");

    // Enroll
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &key_v1 }))
        .to_request();
    test::call_service(&app, req).await;

    // Update
    let req = test::TestRequest::put()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &key_v2 }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // Verify update
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["Key"], key_v2, "Key should be the updated version");
}

#[actix_web::test]
async fn test_put_nonexistent_returns_404() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "dave@test.com");

    let req = test::TestRequest::put()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": B64.encode(b"some-key") }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_delete_key() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "eve@test.com");
    let user_key = B64.encode(b"eves-key");

    // Enroll
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &user_key }))
        .to_request();
    test::call_service(&app, req).await;

    // Delete
    let req = test::TestRequest::delete()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    // Verify gone
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_delete_nonexistent_returns_404() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "frank@test.com");

    let req = test::TestRequest::delete()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_different_users_isolated() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let token_a = make_jwt(&vw_enc, &user_a, "alice@test.com");
    let token_b = make_jwt(&vw_enc, &user_b, "bob@test.com");
    let key_a = B64.encode(b"alice-secret-key");
    let key_b = B64.encode(b"bob-secret-key");

    // Enroll both
    for (token, key) in [(&token_a, &key_a), (&token_b, &key_b)] {
        let req = test::TestRequest::post()
            .uri("/user-keys")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_json(serde_json::json!({ "Key": key }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // Verify isolation: user A gets only their key
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token_a}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["Key"], *key_a);

    // Verify isolation: user B gets only their key
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token_b}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["Key"], *key_b);
}

#[actix_web::test]
async fn test_wrong_signing_key_rejected() {
    // VW decoding key is from one keypair, token signed with a different one
    let (_, _, _, vw_dec) = test_keys();
    let (_, _, attacker_enc, _) = test_keys(); // different keypair
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&attacker_enc, &user_id, "attacker@evil.com");

    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Token signed with wrong key must be rejected");
}

#[actix_web::test]
async fn test_post_different_key_preserves_original() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "frank@test.com");
    let key_a = B64.encode(b"bobs-original-enrollment-key");
    let key_b = B64.encode(b"bobs-DIFFERENT-relogin-key-fresh-from-client");

    // Enroll with key_a
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &key_a }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "First enrollment should succeed");

    // Seed UK_enc in app_data (simulates proxy storing it after enrollment flow)
    state.db.set_user_encrypted_key_if_absent(&user_id, "test_uk_enc").unwrap();

    // Attempt to overwrite with key_b
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &key_b }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "Second POST (re-login) should succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["Key"], key_a, "Re-login POST must return original key (key_a), not new key (key_b)");

    // Ensure GET still returns original key_a
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["Key"], key_a, "GET after re-login must return original key (key_a)");
}

#[actix_web::test]
async fn test_re_enrollment_overwrites_stored_key() {
    // Verifies that when UK_enc is missing from app_data (simulating the scenario
    // after the backfill fix), a POST /user-keys with a different key OVERWRITES
    // the stored key instead of returning the original.
    //
    // This is the POSITIVE control for test_post_different_key_preserves_original:
    // - That test seeds UK_enc → overwrite blocked → original preserved
    // - This test does NOT seed UK_enc → overwrite allowed → new key stored
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);

    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "re-enroll@test.com");
    let key_v1 = B64.encode(b"original-enrollment-key-v1");
    let key_v2 = B64.encode(b"re-enrollment-key-v2");

    // Step 1: Enroll with key_v1
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &key_v1 }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "First enrollment should succeed");

    // Step 2: Verify UK_enc is NOT in app_data (key difference from
    // test_post_different_key_preserves_original which seeds UK_enc)
    let uk_enc = state.db.get_user_encrypted_key(&user_id).unwrap();
    assert!(
        uk_enc.is_none(),
        "UK_enc must not be present — simulating missing app_data after backfill fix"
    );

    // Step 3: POST key_v2 (re-enrollment) — overwrite since UK_enc is missing
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &key_v2 }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "Re-enrollment POST should succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["Key"], key_v2,
        "Re-enrollment POST must return the NEW key (key_v2), proving overwrite happened"
    );

    // Step 4: Verify GET returns key_v2
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "GET should succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["Key"], key_v2,
        "GET after re-enrollment must return the new key (key_v2)"
    );
}

#[actix_web::test]
async fn test_first_enrollment_returns_empty_body() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);
    let app = test::init_service(
        App::new().app_data(state.clone()).configure(api::configure_routes),
    )
    .await;

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "george@test.com");
    let key_a = B64.encode(b"first-enrollment-key");

    // First enrollment POST
    let req = test::TestRequest::post()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "Key": &key_a }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "First POST (enrollment) should succeed");
    let bytes = test::read_body(resp).await;
    assert_eq!(bytes.len(), 0, "Body should be empty on first enrollment");
}

// ============================================================================
// Integration Tests — proxy endpoints (proxy.rs routes)
//
// These tests exercise the overwrite-protection logic in the proxy handlers:
// - POST /api/accounts/set-key-connector-key
// - POST /api/accounts/key
//
// Both handlers are wired as the default_service (catch-all) when proxy is
// enabled. Tests configure a separate app with the proxy handler so that the
// short-circuit paths (existing-key check) can be exercised without needing
// a live Vaultwarden upstream.
// ============================================================================

macro_rules! proxy_app {
    ($state:expr) => {
        test::init_service(
            App::new()
                .app_data($state.clone())
                .configure(api::configure_routes)
                .default_service(web::route().to(proxy::proxy_handler)),
        )
        .await
    };
}

/// POST /api/accounts/key — first enrollment stores the key.
/// Second POST with a DIFFERENT key must NOT overwrite the original.
#[actix_web::test]
async fn test_proxy_accounts_key_overwrite_protection() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);
    let app = proxy_app!(state);

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "proxy-user-a@test.com");
    let key_a = B64.encode(b"proxy-original-user-key-enrollment");
    let key_b = B64.encode(b"proxy-DIFFERENT-user-key-second-login");

    // First enrollment via proxy endpoint POST /api/accounts/key
    let req = test::TestRequest::post()
        .uri("/api/accounts/key")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "key": &key_a }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "First enrollment via /api/accounts/key must succeed");
    // First enrollment returns empty body (no existing key)
    let bytes = test::read_body(resp).await;
    assert_eq!(bytes.len(), 0, "First enrollment must return empty body");

    // Second POST with a different key — must return original key, not overwrite
    let req = test::TestRequest::post()
        .uri("/api/accounts/key")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "key": &key_b }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "Second POST to /api/accounts/key must succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["Key"], key_a,
        "Second POST must return original key (key_a), not the new key (key_b) — overwrite must be blocked"
    );

    // Verify via GET /user-keys that the stored key is still the original
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "GET /user-keys must succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["Key"], key_a,
        "GET /user-keys after second proxy POST must still return the original key (key_a)"
    );
}

/// POST /api/accounts/set-key-connector-key — first enrollment (no existing key)
/// stores the key via the `key` field. Subsequent POSTs with a different key
/// must return the original and prevent overwrite.
#[actix_web::test]
async fn test_proxy_set_key_connector_key_overwrite_protection() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);
    let app = proxy_app!(state);

    let user_id = Uuid::new_v4();
    let token = make_jwt(&vw_enc, &user_id, "proxy-user-b@test.com");
    let key_a = B64.encode(b"set-key-connector-original-enrollment-key");
    let key_b = B64.encode(b"set-key-connector-DIFFERENT-second-login-key");

    // First enrollment: POST /api/accounts/set-key-connector-key with key only (no "keys" obj
    // to avoid VW forwarding attempt). The `key` field triggers handle_set_user_key internally.
    let req = test::TestRequest::post()
        .uri("/api/accounts/set-key-connector-key")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "key": &key_a }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "First enrollment via set-key-connector-key must succeed");
    // First enrollment should return an empty body (no existing key path)
    let bytes = test::read_body(resp).await;
    assert_eq!(bytes.len(), 0, "First enrollment via set-key-connector-key must return empty body");

    // Second POST with a different key — overwrite must be blocked; returns original key
    let req = test::TestRequest::post()
        .uri("/api/accounts/set-key-connector-key")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "key": &key_b }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200, "Second POST to set-key-connector-key must succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["Key"], key_a,
        "Second POST must return original key (key_a) — overwrite must be blocked"
    );

    // Confirm via GET /user-keys that the DB key is still the original
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["Key"], key_a,
        "GET /user-keys after set-key-connector-key second POST must return original key"
    );
}

/// POST /api/accounts/set-key-connector-key without auth must return 401.
#[actix_web::test]
async fn test_proxy_set_key_connector_key_no_auth_returns_401() {
    let (_, _, _, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);
    let app = proxy_app!(state);

    let key_a = B64.encode(b"some-key");

    let req = test::TestRequest::post()
        .uri("/api/accounts/set-key-connector-key")
        .set_json(serde_json::json!({ "key": &key_a }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Request without Bearer token must be rejected with 401");
}

/// POST /api/accounts/key without auth must return 401.
#[actix_web::test]
async fn test_proxy_accounts_key_no_auth_returns_401() {
    let (_, _, _, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);
    let app = proxy_app!(state);

    let key_a = B64.encode(b"some-key");

    let req = test::TestRequest::post()
        .uri("/api/accounts/key")
        .set_json(serde_json::json!({ "key": &key_a }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Request without Bearer token must be rejected with 401");
}

/// Two different users share the same proxy app but their keys must remain isolated.
/// Enrolling user A via /api/accounts/key, then user B — each GET must return their
/// own key and NOT the other user's.
#[actix_web::test]
async fn test_proxy_accounts_key_user_isolation() {
    let (_, _, vw_enc, vw_dec) = test_keys();
    let (app_priv, app_pub, _, _) = test_keys();
    let state = build_app_state(vw_dec, &app_priv, &app_pub);
    let app = proxy_app!(state);

    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let token_a = make_jwt(&vw_enc, &user_a, "proxy-alice@test.com");
    let token_b = make_jwt(&vw_enc, &user_b, "proxy-bob@test.com");
    let key_a = B64.encode(b"proxy-alice-unique-vault-key");
    let key_b = B64.encode(b"proxy-bob-unique-vault-key");

    // Enroll user A
    let req = test::TestRequest::post()
        .uri("/api/accounts/key")
        .insert_header(("Authorization", format!("Bearer {token_a}")))
        .set_json(serde_json::json!({ "key": &key_a }))
        .to_request();
    test::call_service(&app, req).await;

    // Enroll user B
    let req = test::TestRequest::post()
        .uri("/api/accounts/key")
        .insert_header(("Authorization", format!("Bearer {token_b}")))
        .set_json(serde_json::json!({ "key": &key_b }))
        .to_request();
    test::call_service(&app, req).await;

    // User A retrieves their key — must be key_a, not key_b
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token_a}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["Key"], key_a, "User A must retrieve their own key, not user B's");

    // User B retrieves their key — must be key_b, not key_a
    let req = test::TestRequest::get()
        .uri("/user-keys")
        .insert_header(("Authorization", format!("Bearer {token_b}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["Key"], key_b, "User B must retrieve their own key, not user A's");
}
