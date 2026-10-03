use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A sealed vault key entry persisted in the database
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StoredKeyEntry {
    pub user_id: Uuid,
    pub encrypted_key: Vec<u8>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub last_access_at: Option<NaiveDateTime>,
}

/// Generic configuration / state entry persisted in the database
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConfigEntry {
    pub key: String,
    pub value: String,
}

/// Inbound payload for key enrollment or update
#[derive(Debug, Deserialize)]
pub struct KeyEnrollPayload {
    #[serde(alias = "Key", alias = "key")]
    pub key: String,
}

/// Outbound payload when retrieving a vault key
#[derive(Debug, Serialize)]
pub struct KeyRetrievalPayload {
    #[serde(rename = "Key")]
    pub key: String,
}

/// Claims extracted from a validated JWT
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub email: String,
}

/// Compatibility matrix returned by GET /version
#[derive(Debug, Clone, Serialize)]
pub struct CompatibilityInfo {
    /// Vaultwarden version this build was tested against (COMPAT_VW_VERSION)
    pub vaultwarden: String,
    /// Vaultwarden version actually detected at runtime (None = unreachable)
    pub vaultwarden_detected: Option<String>,
    /// Verdict of `vaultwarden_detected` against `vaultwarden`
    pub status: String,
    pub keycloak: String,
    pub clients: ClientVersions,
    pub last_tested: String,
    pub status_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientVersions {
    pub web: String,
    pub desktop: String,
    pub browser_extension: String,
    pub mobile: String,
}

/// GET /version response
#[derive(Debug, Clone, Serialize)]
pub struct VersionResponse {
    pub version: String,
    pub build: String,
    pub compatibility: CompatibilityInfo,
    pub alive: bool,
}
