use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub vaultwarden_url: String,
    pub vaultwarden_rsa_public_key_file: String,
    pub database_path: String,
    pub rsa_private_key_file: String,
    pub rsa_public_key_file: String,
    pub log_level: String,
    /// Enable reverse proxy mode (clients connect here, requests forwarded to VW)
    pub proxy_enabled: bool,
    /// The externally-reachable URL of /user-keys (injected into VW responses)
    pub user_keys_url: String,
    /// Hours between automatic wrapping-secret rotations (0 = disabled)
    pub rotation_interval_hours: u64,
    /// The external DOMAIN of Vaultwarden (used for JWT issuer validation)
    pub domain: Option<String>,
    /// TLS certificate file (optional, for HTTPS support)
    pub tls_cert_file: Option<String>,
    /// TLS private key file (optional, for HTTPS support)
    pub tls_key_file: Option<String>,
    /// Display name for the synthetic organization injected when the user has no orgs
    pub synthetic_org_name: String,
    /// Identifier for the synthetic organization (used by the client in API calls)
    pub synthetic_org_identifier: String,
    /// Build SHA injected at compile time (optional)
    pub build_sha: String,
    /// Tested Vaultwarden version for compatibility reporting
    pub compat_vw_version: String,
    /// Tested Keycloak version for compatibility reporting
    pub compat_kc_version: String,
    /// Tested Bitwarden client versions (JSON string, optional)
    pub compat_clients: String,
    /// Date of last compatibility test (ISO 8601)
    pub compat_last_tested: String,
    /// URL of the compatibility matrix published for this build
    pub compat_status_url: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Config {
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8484".to_string())
                .parse()
                .unwrap_or(8484),
            vaultwarden_url: env::var("VAULTWARDEN_URL")
                .map_err(|_| anyhow::anyhow!("VAULTWARDEN_URL is required"))?,
            vaultwarden_rsa_public_key_file: env::var("VAULTWARDEN_RSA_PUBLIC_KEY_FILE")
                .map_err(|_| anyhow::anyhow!("VAULTWARDEN_RSA_PUBLIC_KEY_FILE is required"))?,
            database_path: env::var("DATABASE_PATH")
                .unwrap_or_else(|_| "./data/masterless.sqlite".to_string()),
            rsa_private_key_file: env::var("RSA_PRIVATE_KEY_FILE")
                .unwrap_or_else(|_| "./data/rsa_private.pem".to_string()),
            rsa_public_key_file: env::var("RSA_PUBLIC_KEY_FILE")
                .unwrap_or_else(|_| "./data/rsa_public.pem".to_string()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            proxy_enabled: env::var("PROXY_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            user_keys_url: env::var("USER_KEYS_URL")
                .unwrap_or_else(|_| String::new()),
            rotation_interval_hours: env::var("ROTATION_INTERVAL_HOURS")
                .unwrap_or_else(|_| "0".to_string())
                .parse()
                .unwrap_or(0),
            domain: env::var("DOMAIN").ok(),
            tls_cert_file: env::var("TLS_CERT_FILE").ok(),
            tls_key_file: env::var("TLS_KEY_FILE").ok(),
            synthetic_org_name: env::var("SYNTHETIC_ORG_NAME")
                .unwrap_or_else(|_| "Vaultwarden Masterless".to_string()),
            synthetic_org_identifier: env::var("SYNTHETIC_ORG_IDENTIFIER")
                .unwrap_or_else(|_| "vaultwarden-masterless".to_string()),
            build_sha: env::var("BUILD_SHA").unwrap_or_else(|_| String::new()),
            compat_vw_version: env::var("COMPAT_VW_VERSION").unwrap_or_else(|_| "1.37.3".to_string()),
            compat_kc_version: env::var("COMPAT_KC_VERSION").unwrap_or_else(|_| "26.3.4".to_string()),
            compat_clients: env::var("COMPAT_CLIENTS").unwrap_or_else(|_| r#"{"web":"2024.x - 2026.x","desktop":"2024.x - 2026.x","browser_extension":"2024.x - 2026.x","mobile":"untested"}"#.to_string()),
            compat_last_tested: env::var("COMPAT_LAST_TESTED").unwrap_or_else(|_| "2026-09-18".to_string()),
            compat_status_url: env::var("COMPAT_STATUS_URL").unwrap_or_else(|_| "https://github.com/antoniolago/vaultwarden-masterless/blob/main/COMPATIBILITY.md".to_string()),
        })
    }
}
