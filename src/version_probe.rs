//! Runtime detection of the Vaultwarden version the proxy sits in front of.
//!
//! `GET /version` reports the Vaultwarden version vaultwarden-masterless was
//! *tested* against (`COMPAT_VW_VERSION`). This module answers the other half of
//! the question: which Vaultwarden is running right now. Operators get both plus
//! a `status` verdict, so a Vaultwarden upgrade that nobody re-tested surfaces as
//! `newer` instead of passing silently as "compatible".
//!
//! Detection is best-effort by design: a failed probe must never block startup
//! or break `/version`. It reports `unreachable` and tries again later.

use std::time::Duration;

/// Vaultwarden answers `GET /api/version` with a bare JSON string (`"1.37.2"`).
/// Older builds only expose the version inside `GET /api/config`, so we try both.
const VERSION_PATHS: [&str; 2] = ["/api/version", "/api/config"];
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Compatibility verdict returned by `GET /version`.
pub mod status {
    /// Detected version is the one we test against.
    pub const MATCH: &str = "match";
    /// Detected version is newer than the tested one — untested territory.
    pub const NEWER: &str = "newer";
    /// Detected version is older than the tested one.
    pub const OLDER: &str = "older";
    /// Vaultwarden could not be reached, so nothing can be said.
    pub const UNREACHABLE: &str = "unreachable";
    /// Something answered, but the version strings were unusable.
    pub const UNKNOWN: &str = "unknown";
}

/// Parse `major.minor.patch`, tolerating a leading `v`, surrounding quotes and a
/// pre-release/build suffix (`1.37.3-alpine`). Missing components default to 0.
pub fn parse_version(raw: &str) -> Option<(u64, u64, u64)> {
    let cleaned = raw.trim().trim_matches('"').trim_start_matches('v');
    let core = cleaned.split(['-', '+']).next().unwrap_or(cleaned);
    let mut parts = core.split('.');

    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;

    Some((major, minor, patch))
}

/// Verdict for a detected version against the version this build was tested on.
pub fn status_for(detected: Option<&str>, tested: &str) -> &'static str {
    let Some(detected) = detected else {
        return status::UNREACHABLE;
    };

    let (Some(detected), Some(tested)) = (parse_version(detected), parse_version(tested)) else {
        return status::UNKNOWN;
    };

    match detected.cmp(&tested) {
        std::cmp::Ordering::Equal => status::MATCH,
        std::cmp::Ordering::Greater => status::NEWER,
        std::cmp::Ordering::Less => status::OLDER,
    }
}

/// Ask Vaultwarden for its version.
///
/// Returns `None` when it is unreachable or answers in a shape we don't
/// understand. Never panics, never propagates an error.
pub async fn detect(client: &reqwest::Client, base_url: &str) -> Option<String> {
    let base = base_url.trim_end_matches('/');

    for path in VERSION_PATHS {
        let Ok(response) = client
            .get(format!("{base}{path}"))
            .timeout(PROBE_TIMEOUT)
            .send()
            .await
        else {
            continue;
        };

        if !response.status().is_success() {
            continue;
        }

        let Ok(body) = response.json::<serde_json::Value>().await else {
            continue;
        };

        // `/api/version` is a bare string; `/api/config` carries `version`.
        let candidate = match &body {
            serde_json::Value::String(value) => Some(value.clone()),
            value => value
                .get("version")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        };

        if let Some(version) = candidate.filter(|v| parse_version(v).is_some()) {
            return Some(version);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versions_in_the_shapes_vaultwarden_answers_with() {
        assert_eq!(parse_version("1.37.3"), Some((1, 37, 3)));
        assert_eq!(parse_version("\"1.37.2\""), Some((1, 37, 2)));
        assert_eq!(parse_version(" v1.35.8 "), Some((1, 35, 8)));
        assert_eq!(parse_version("1.37.3-alpine"), Some((1, 37, 3)));
        assert_eq!(parse_version("1.37"), Some((1, 37, 0)));
    }

    #[test]
    fn rejects_what_is_not_a_version() {
        assert_eq!(parse_version("garbage"), None);
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("latest"), None);
    }

    #[test]
    fn compares_numerically_not_lexically() {
        // "1.9.0" sorts after "1.37.3" as text, but it is an older release
        assert_eq!(status_for(Some("1.9.0"), "1.37.3"), status::OLDER);
        assert_eq!(status_for(Some("1.36.0"), "1.37.3"), status::OLDER);
        assert_eq!(status_for(Some("1.37.3"), "1.37.3"), status::MATCH);
        assert_eq!(status_for(Some("1.37.4"), "1.37.3"), status::NEWER);
        assert_eq!(status_for(Some("2.0.0"), "1.37.3"), status::NEWER);
    }

    #[test]
    fn reports_unreachable_and_unknown_separately() {
        assert_eq!(status_for(None, "1.37.3"), status::UNREACHABLE);
        assert_eq!(status_for(Some("1.37.3"), "not-a-version"), status::UNKNOWN);
    }

    #[actix_web::test]
    async fn detect_returns_none_when_vaultwarden_is_unreachable() {
        // Nothing is listening on this port: detection must degrade to None
        let client = reqwest::Client::new();
        assert_eq!(detect(&client, "http://127.0.0.1:1").await, None);
    }
}
