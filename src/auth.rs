use actix_web::HttpRequest;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use uuid::Uuid;

use crate::config::Config;
use crate::errors::{AppError, AppResult};
use crate::models::AuthenticatedUser;

/// JWT claims from Vaultwarden's access tokens.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VaultwardenClaims {
    /// Subject — the user UUID
    sub: String,
    /// Email
    email: Option<String>,
    /// Authentication method
    amr: Option<Vec<String>>,
    /// Scope
    scope: Option<Vec<String>>,
    /// Expiration
    exp: u64,
    /// Issuer
    iss: Option<String>,
}

/// Validates the Bearer token from the request against Vaultwarden's RSA public key.
pub fn extract_authenticated_user(
    req: &HttpRequest,
    vw_decoding_key: &DecodingKey,
    vw_url: &str,
    domain: Option<&str>,
) -> AppResult<AuthenticatedUser> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::AuthError("Missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::AuthError("Invalid Authorization header format".to_string()))?;

    let mut validation = Validation::new(Algorithm::RS256);
    let issuer = vw_url.trim_end_matches('/').to_string();
    let mut issuers: Vec<String> = vec![issuer.clone(), format!("{issuer}|login")];
    // Also accept tokens issued with VW's DOMAIN (proxy URL) as issuer
    if let Some(domain) = domain {
        let d = domain.trim_end_matches('/').to_string();
        if d != issuer {
            issuers.push(d.clone());
            issuers.push(format!("{d}|login"));
        }
    }
    let issuer_refs: Vec<&str> = issuers.iter().map(|s| s.as_str()).collect();
    validation.set_issuer(&issuer_refs);
    validation.set_audience(&["authenticated"]);
    validation.validate_aud = false; // Vaultwarden tokens may not have aud

    let token_data = decode::<VaultwardenClaims>(token, vw_decoding_key, &validation)
        .map_err(|e| AppError::AuthError(format!("JWT validation failed: {e}")))?;

    let claims = token_data.claims;

    // Verify this is an SSO or application auth
    if let Some(ref amr) = claims.amr {
        let valid_methods = ["Application", "external", "sso"];
        if !amr.iter().any(|m| valid_methods.contains(&m.as_str())) {
            return Err(AppError::AuthError(format!(
                "Invalid auth method: {amr:?}. Requires SSO/external authentication."
            )));
        }
    }

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| AppError::AuthError(format!("Invalid user ID in token: {e}")))?;

    Ok(AuthenticatedUser {
        user_id,
        email: claims.email.unwrap_or_default(),
    })
}

/// Load the Vaultwarden RSA public key for JWT verification.
pub fn load_vw_decoding_key(path: &str) -> AppResult<DecodingKey> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| AppError::InternalError(format!("Cannot read VW RSA public key at {path}: {e}")))?;

    DecodingKey::from_rsa_pem(pem.as_bytes())
        .map_err(|e| AppError::InternalError(format!("Invalid RSA public key PEM: {e}")))
}

/// Authenticate the incoming request by validating the Vaultwarden-issued JWT.
pub async fn authenticate_request(
    req: &HttpRequest,
    vw_decoding_key: &DecodingKey,
    config: &Config,
) -> AppResult<AuthenticatedUser> {
    extract_authenticated_user(req, vw_decoding_key, &config.vaultwarden_url, config.domain.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        email: String,
        amr: Vec<String>,
        exp: u64,
        iss: String,
    }

    fn generate_test_keys() -> (EncodingKey, DecodingKey) {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let public_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();

        let encoding = EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();
        let decoding = DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap();

        (encoding, decoding)
    }

    fn make_token(encoding_key: &EncodingKey, claims: &TestClaims) -> String {
        let header = Header::new(Algorithm::RS256);
        encode(&header, claims, encoding_key).unwrap()
    }

    #[test]
    fn test_valid_jwt_extraction() {
        let (enc_key, dec_key) = generate_test_keys();
        let user_id = Uuid::new_v4();
        let claims = TestClaims {
            sub: user_id.to_string(),
            email: "test@example.com".to_string(),
            amr: vec!["Application".to_string()],
            exp: (chrono::Utc::now().timestamp() + 3600) as u64,
            iss: "https://vw.example.com|login".to_string(),
        };
        let token = make_token(&enc_key, &claims);

        let req = actix_web::test::TestRequest::default()
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_http_request();

        let result = extract_authenticated_user(&req, &dec_key, "https://vw.example.com", None);
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.user_id, user_id);
        assert_eq!(user.email, "test@example.com");
    }

    #[test]
    fn test_missing_auth_header() {
        let (_, dec_key) = generate_test_keys();
        let req = actix_web::test::TestRequest::default().to_http_request();
        let result = extract_authenticated_user(&req, &dec_key, "https://vw.example.com", None);
        assert!(matches!(result, Err(AppError::AuthError(_))));
    }

    #[test]
    fn test_expired_token() {
        let (enc_key, dec_key) = generate_test_keys();
        let claims = TestClaims {
            sub: Uuid::new_v4().to_string(),
            email: "test@example.com".to_string(),
            amr: vec!["Application".to_string()],
            exp: 1000, // long expired
            iss: "https://vw.example.com|login".to_string(),
        };
        let token = make_token(&enc_key, &claims);

        let req = actix_web::test::TestRequest::default()
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_http_request();

        let result = extract_authenticated_user(&req, &dec_key, "https://vw.example.com", None);
        assert!(matches!(result, Err(AppError::AuthError(_))));
    }
}
