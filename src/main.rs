#![recursion_limit = "256"]

mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod errors;
mod models;
mod proxy;
mod version_probe;

use std::sync::Arc;

use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{web, App, HttpServer};
use tracing_subscriber::EnvFilter;

use crate::api::AppState;
use crate::config::Config;
use crate::crypto::VaultKeyManager;
use crate::db::Database;

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if present
    let _ = dotenvy::dotenv();

    // Load configuration
    let config = Config::from_env()?;

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.log_level)),
        )
        .init();

    tracing::info!("Starting vaultwarden-masterless v{}", env!("CARGO_PKG_VERSION"));

    // Open database
    let database = Database::open(&config.database_path)?;
    tracing::info!("Database opened at {}", config.database_path);

    // Initialize crypto service
    let rsa_private_pem = std::fs::read_to_string(&config.rsa_private_key_file)
        .map_err(|e| anyhow::anyhow!("Cannot read RSA private key at {}: {e}", config.rsa_private_key_file))?;
    let rsa_public_pem = std::fs::read_to_string(&config.rsa_public_key_file)
        .map_err(|e| anyhow::anyhow!("Cannot read RSA public key at {}: {e}", config.rsa_public_key_file))?;

    let crypto = VaultKeyManager::new(&rsa_private_pem, &rsa_public_pem)?;
    crypto.bootstrap_wrapping_key(&database)?;
    tracing::info!("Vault key manager initialized");

    // Check if wrapping secret rotation is due on startup
    if config.rotation_interval_hours > 0 {
        check_and_rotate(&crypto, &database, config.rotation_interval_hours)?;
    } else {
        tracing::info!("Automatic wrapping-secret rotation is disabled (ROTATION_INTERVAL_HOURS=0)");
    }

    // Load Vaultwarden JWT verification key
    let vw_decoding_key = auth::load_vw_decoding_key(&config.vaultwarden_rsa_public_key_file)?;
    tracing::info!("Vaultwarden JWT verification key loaded");

    let db = Arc::new(database);
    let crypto = Arc::new(crypto);
    let config = Arc::new(config);

    let bind_host = config.host.clone();
    let bind_port = config.port;

    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Failed to build HTTP client");

    let app_state = web::Data::new(AppState {
        db: db.clone(),
        crypto: crypto.clone(),
        config: config.clone(),
        vw_decoding_key,
        http_client,
        sso_cookies: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        vw_version: tokio::sync::Mutex::new(None),
    });

    // Detect which Vaultwarden we are actually in front of, and keep re-checking:
    // an upgrade nobody re-tested must surface in GET /version instead of passing
    // silently as compatible. A failed probe never blocks startup.
    {
        let probe_state = app_state.clone();
        tokio::spawn(async move {
            loop {
                let detected = version_probe::detect(
                    &probe_state.http_client,
                    &probe_state.config.vaultwarden_url,
                )
                .await;

                match &detected {
                    Some(version) => {
                        let status = version_probe::status_for(
                            Some(version.as_str()),
                            &probe_state.config.compat_vw_version,
                        );
                        if status == version_probe::status::MATCH {
                            tracing::info!(
                                "Vaultwarden {version} detected — matches the tested version"
                            );
                        } else {
                            tracing::warn!(
                                "Vaultwarden {version} detected — tested against {} ({status}); see COMPATIBILITY.md",
                                probe_state.config.compat_vw_version
                            );
                        }
                    }
                    None => tracing::debug!("Vaultwarden version not detected (unreachable)"),
                }

                // Retry quickly until Vaultwarden answers, then settle into a
                // periodic check so long-running pods notice an upgrade.
                let delay_secs = if detected.is_some() { 6 * 3600 } else { 60 };
                *probe_state.vw_version.lock().await = detected;
                tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
            }
        });
    }

    // Rate limiter: burst of 30 requests, refills 1 token per 2 seconds
    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(2)
        .burst_size(30)
        .finish()
        .expect("Failed to build rate limiter config");

    // Spawn background rotation task if configured
    if config.rotation_interval_hours > 0 {
        let bg_crypto = crypto.clone();
        let bg_db = db.clone();
        let interval_hours = config.rotation_interval_hours;
        tokio::spawn(async move {
            // Check once per hour whether rotation is due
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            interval.tick().await; // skip the immediate first tick (already checked on startup)
            loop {
                interval.tick().await;
                if let Err(e) = check_and_rotate(&bg_crypto, &bg_db, interval_hours) {
                    tracing::error!("Background rotation check failed: {e}");
                }
            }
        });
        tracing::info!("Background rotation task started (interval: {}h)", config.rotation_interval_hours);
    }

    let proxy_enabled = config.proxy_enabled;
    if proxy_enabled {
        tracing::info!("Proxy mode ENABLED — clients should connect to this service");
        tracing::info!("Proxying to Vaultwarden at {}", config.vaultwarden_url);
        if config.user_keys_url.is_empty() {
            tracing::warn!("USER_KEYS_URL is empty — passwordless flags won't be injected");
        }
    }

    tracing::info!("Listening on {bind_host}:{bind_port}");

    // Load and configure TLS if certificates are provided
    let tls_config = if let (Some(cert_file), Some(key_file)) = (&config.tls_cert_file, &config.tls_key_file) {
        tracing::info!("Loading TLS certificate from {}", cert_file);
        
        let cert_bytes = std::fs::read(cert_file)
            .map_err(|e| anyhow::anyhow!("Failed to read TLS certificate: {e}"))?;
        let key_bytes = std::fs::read(key_file)
            .map_err(|e| anyhow::anyhow!("Failed to read TLS private key: {e}"))?;

        // Parse certificates
        let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_bytes[..])
            .map_err(|e| anyhow::anyhow!("Failed to parse TLS certificate: {e}"))?
            .into_iter()
            .map(rustls::Certificate)
            .collect();
        
        if certs.is_empty() {
            return Err(anyhow::anyhow!("No certificates found in file"));
        }
        
        // Parse private key
        let mut key_reader = &key_bytes[..];
        let key_bytes_vec = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
            .map_err(|e| anyhow::anyhow!("Failed to parse TLS private key: {e}"))?;
        
        if key_bytes_vec.is_empty() {
            return Err(anyhow::anyhow!("No private key found in file"));
        }
        
        let key = rustls::PrivateKey(key_bytes_vec[0].clone());

        let mut cfg = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("Failed to build TLS config: {e}"))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        tracing::info!("TLS enabled on {bind_host}:{bind_port}");
        Some(cfg)
    } else {
        tracing::info!("TLS not configured (TLS_CERT_FILE and TLS_KEY_FILE not set)");
        None
    };

    let server = HttpServer::new(move || {
        let mut app = App::new()
            .app_data(app_state.clone())
            .route("/alive", web::get().to(api::alive))
            .route("/version", web::get().to(api::version))
            .service(
                web::scope("/user-keys")
                    .wrap(Governor::new(&governor_conf))
                    .route("", web::get().to(api::get_user_key))
                    .route("", web::post().to(api::post_user_key))
                    .route("", web::put().to(api::put_user_key))
                    .route("", web::delete().to(api::delete_user_key))
            );

        if proxy_enabled {
            // Catch-all: everything not matched gets proxied to Vaultwarden
            app = app.default_service(web::route().to(proxy::proxy_handler));
        }

        app
    });

    // Apply TLS configuration if available, otherwise bind without TLS
    if let Some(cfg) = tls_config {
        server
            .bind_rustls((bind_host.as_str(), bind_port), cfg)?
            .run()
            .await
            .map_err(|e| anyhow::anyhow!("Server error: {e}"))
    } else {
        server
            .bind((bind_host.as_str(), bind_port))?
            .run()
            .await
            .map_err(|e| anyhow::anyhow!("Server error: {e}"))
    }
}

/// Check if the wrapping secret needs rotation based on the configured interval.
/// Rotation is safe and atomic — if anything fails, the DB is unchanged.
fn check_and_rotate(
    crypto: &VaultKeyManager,
    db: &Database,
    interval_hours: u64,
) -> anyhow::Result<()> {
    let needs_rotation = match db.get_app_data("last_rotation_at")? {
        None => {
            tracing::info!("No previous rotation recorded — rotating now");
            true
        }
        Some(ts_str) => {
            let last = chrono::NaiveDateTime::parse_from_str(&ts_str, "%Y-%m-%dT%H:%M:%S%.fZ")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(&ts_str, "%Y-%m-%dT%H:%M:%SZ"))
                .unwrap_or_else(|_| chrono::Utc::now().naive_utc());
            let elapsed = chrono::Utc::now().naive_utc().signed_duration_since(last);
            let due = elapsed.num_hours() >= interval_hours as i64;
            if due {
                tracing::info!(
                    "Wrapping secret rotation due (last: {}, {}h ago, interval: {}h)",
                    ts_str,
                    elapsed.num_hours(),
                    interval_hours
                );
            } else {
                tracing::debug!(
                    "Rotation not due yet (last: {}, {}h ago, interval: {}h)",
                    ts_str,
                    elapsed.num_hours(),
                    interval_hours
                );
            }
            due
        }
    };

    if needs_rotation {
        let count = crypto.rotate_wrapping_secret(db)?;
        tracing::info!("Rotation complete — {count} user key(s) re-encrypted");
    }

    Ok(())
}
