use crate::{config::Config, error::AppError};
use argon2::{password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String,
    pub sid: String,
    pub ver: i64,
    pub iss: String,
    pub aud: String,
    pub iat: usize,
    pub exp: usize,
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    if password.len() < 12 || password.len() > 128 {
        return Err(AppError::Validation("Password must be 12–128 bytes long".to_string()));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AppError::Internal)
}

pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded_hash) else { return false; };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

pub fn new_opaque_token() -> String {
    let mut token = [0_u8; 32];
    OsRng.fill_bytes(&mut token);
    URL_SAFE_NO_PAD.encode(token)
}

pub fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub fn new_refresh_token(session_id: Uuid) -> String {
    format!("{}.{}", session_id, new_opaque_token())
}

pub fn session_id_from_refresh(token: &str) -> Result<Uuid, AppError> {
    let (session_id, secret) = token.split_once('.').ok_or(AppError::Unauthorized)?;
    if secret.len() < 40 || secret.len() > 64 { return Err(AppError::Unauthorized); }
    Uuid::parse_str(session_id).map_err(|_| AppError::Unauthorized)
}

pub fn issue_access_token(user_id: Uuid, session_id: Uuid, auth_version: i64, config: &Config) -> Result<String, AppError> {
    let now = Utc::now().timestamp().max(0) as usize;
    let ttl = config.access_token_ttl_seconds.clamp(60, 3600) as usize;
    let claims = AccessClaims {
        sub: user_id.to_string(),
        sid: session_id.to_string(),
        ver: auth_version,
        iss: config.jwt_issuer.clone(),
        aud: config.jwt_audience.clone(),
        iat: now,
        exp: now + ttl,
    };
    encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(config.jwt_secret.as_bytes()))
        .map_err(|_| AppError::Internal)
}

pub fn decode_access_token(token: &str, config: &Config) -> Result<AccessClaims, AppError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[config.jwt_issuer.as_str()]);
    validation.set_audience(&[config.jwt_audience.as_str()]);
    let decoded = decode::<AccessClaims>(token, &DecodingKey::from_secret(config.jwt_secret.as_bytes()), &validation)
        .map_err(|_| AppError::Unauthorized)?;
    Ok(decoded.claims)
}

pub fn refresh_expiry(config: &Config) -> chrono::DateTime<Utc> {
    Utc::now() + Duration::days(config.refresh_token_ttl_days.clamp(1, 90))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_tokens_have_high_entropy_and_sha256_digests() {
        let token = new_opaque_token();
        assert_eq!(token.len(), 43); // 32 random bytes, base64url without padding.
        assert_eq!(hash_token(&token).len(), 32);
        assert_ne!(hash_token("token-a"), hash_token("token-b"));
    }

    #[test]
    fn refresh_token_binds_a_session_uuid_and_random_secret() {
        let session_id = Uuid::new_v4();
        let refresh = new_refresh_token(session_id);
        assert_eq!(session_id_from_refresh(&refresh).expect("valid refresh token"), session_id);
        assert!(session_id_from_refresh("not-a-refresh-token").is_err());
    }

    #[test]
    fn password_hash_verifies_only_the_original_password() {
        let password = "a-long-and-unique-test-password";
        let encoded = hash_password(password).expect("password should hash");
        assert!(verify_password(password, &encoded));
        assert!(!verify_password("incorrect-password", &encoded));
    }
}
