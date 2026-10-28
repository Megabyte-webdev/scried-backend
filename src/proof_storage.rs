use crate::{
    config::{Config, ProofStorageConfig},
    error::AppError,
};
use reqwest::{multipart, Client, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;

#[derive(Clone)]
pub struct ProofStorage {
    backend: Backend,
}

#[derive(Clone)]
enum Backend {
    Local {
        root: PathBuf,
    },
    Cloudinary {
        cloud_name: String,
        api_key: String,
        api_secret: String,
        client: Client,
    },
}

#[derive(Deserialize)]
struct UploadResponse {
    asset_id: String,
}

impl ProofStorage {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let backend = match &config.proof_storage {
            ProofStorageConfig::Local => Backend::Local {
                root: config.private_storage_dir.clone(),
            },
            ProofStorageConfig::Cloudinary {
                cloud_name,
                api_key,
                api_secret,
            } => Backend::Cloudinary {
                cloud_name: cloud_name.clone(),
                api_key: api_key.clone(),
                api_secret: api_secret.clone(),
                client: Client::builder().timeout(Duration::from_secs(30)).build()?,
            },
        };
        Ok(Self { backend })
    }

    pub async fn initialize(&self) -> Result<(), AppError> {
        if let Backend::Local { root } = &self.backend {
            tokio::fs::create_dir_all(root).await.map_err(|error| {
                tracing::error!(path = %root.display(), error = %error, "could not initialize local proof storage");
                AppError::Internal
            })?;
        }
        Ok(())
    }

    pub async fn store(
        &self,
        application_id: Uuid,
        proof_id: Uuid,
        extension: &str,
        mime_type: &str,
        bytes: &[u8],
    ) -> Result<String, AppError> {
        match &self.backend {
            Backend::Local { root } => {
                let key = format!("{application_id}/{proof_id}.{extension}");
                let path = crate::proofs::safe_storage_path(root, &key)?;
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                tokio::fs::write(path, bytes).await?;
                Ok(key)
            }
            Backend::Cloudinary {
                cloud_name,
                api_key,
                api_secret,
                client,
            } => {
                let resource_type = if extension == "pdf" { "raw" } else { "image" };
                let mut public_id = format!("scried/proofs/{application_id}/{proof_id}");
                if resource_type == "raw" {
                    public_id.push_str(".pdf");
                }
                let timestamp = chrono::Utc::now().timestamp().to_string();
                let parameters =
                    format!("public_id={public_id}&timestamp={timestamp}&type=authenticated");
                let signature =
                    format!("{:x}", Sha256::digest(format!("{parameters}{api_secret}")));
                let file = multipart::Part::bytes(bytes.to_vec())
                    .file_name(format!("{proof_id}.{extension}"))
                    .mime_str(mime_type)
                    .map_err(|error| {
                        tracing::error!(error = %error, "invalid proof MIME type for Cloudinary upload");
                        AppError::Internal
                    })?;
                let form = multipart::Form::new()
                    .text("api_key", api_key.clone())
                    .text("timestamp", timestamp)
                    .text("public_id", public_id)
                    .text("type", "authenticated")
                    .text("signature", signature)
                    .part("file", file);
                let response = client
                    .post(format!(
                        "https://api.cloudinary.com/v1_1/{cloud_name}/{resource_type}/upload"
                    ))
                    .multipart(form)
                    .send()
                    .await
                    .map_err(|error| {
                        tracing::error!(error = %error, "Cloudinary proof upload request failed");
                        AppError::Unavailable
                    })?;
                if !response.status().is_success() {
                    tracing::error!(status = %response.status(), "Cloudinary rejected proof upload");
                    return Err(AppError::Unavailable);
                }
                let result = response.json::<UploadResponse>().await.map_err(|error| {
                    tracing::error!(error = %error, "invalid Cloudinary upload response");
                    AppError::Unavailable
                })?;
                let key = format!("cloudinary/{resource_type}/{}", result.asset_id);
                parse_cloudinary_key(&key)?;
                Ok(key)
            }
        }
    }

    pub async fn read(&self, key: &str) -> Result<Vec<u8>, AppError> {
        match &self.backend {
            Backend::Local { root } => {
                let path = crate::proofs::safe_storage_path(root, key)?;
                tokio::fs::read(path).await.map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        AppError::NotFound
                    } else {
                        AppError::from(error)
                    }
                })
            }
            Backend::Cloudinary {
                cloud_name,
                api_key,
                api_secret,
                client,
            } => {
                let (resource_type, asset_id) = parse_cloudinary_key(key)?;
                let timestamp = chrono::Utc::now().timestamp().to_string();
                let parameters =
                    format!("asset_id={asset_id}&attachment=true&timestamp={timestamp}");
                let signature =
                    format!("{:x}", Sha256::digest(format!("{parameters}{api_secret}")));
                let response = client
                    .post(format!(
                        "https://api.cloudinary.com/v1_1/{cloud_name}/asset/download"
                    ))
                    .form(&[
                        ("asset_id", asset_id),
                        ("attachment", "true"),
                        ("timestamp", timestamp.as_str()),
                        ("api_key", api_key.as_str()),
                        ("signature", signature.as_str()),
                    ])
                    .send()
                    .await
                    .map_err(|error| {
                        tracing::error!(error = %error, "Cloudinary proof download request failed");
                        AppError::Unavailable
                    })?;
                if response.status() == StatusCode::NOT_FOUND {
                    return Err(AppError::NotFound);
                }
                if !response.status().is_success() {
                    tracing::error!(status = %response.status(), resource_type, "Cloudinary could not download proof");
                    return Err(AppError::Unavailable);
                }
                response
                    .bytes()
                    .await
                    .map(|bytes| bytes.to_vec())
                    .map_err(|error| {
                        tracing::error!(error = %error, "could not read Cloudinary proof response");
                        AppError::Unavailable
                    })
            }
        }
    }

    pub async fn delete(&self, key: &str) -> Result<(), AppError> {
        match &self.backend {
            Backend::Local { root } => {
                let path = crate::proofs::safe_storage_path(root, key)?;
                match tokio::fs::remove_file(path).await {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(AppError::from(error)),
                }
            }
            Backend::Cloudinary {
                cloud_name,
                api_key,
                api_secret,
                client,
            } => {
                let (resource_type, asset_id) = parse_cloudinary_key(key)?;
                let timestamp = chrono::Utc::now().timestamp().to_string();
                let parameters =
                    format!("asset_id={asset_id}&invalidate=true&timestamp={timestamp}");
                let signature =
                    format!("{:x}", Sha256::digest(format!("{parameters}{api_secret}")));
                let response = client
                    .post(format!(
                        "https://api.cloudinary.com/v1_1/{cloud_name}/{resource_type}/destroy"
                    ))
                    .form(&[
                        ("asset_id", asset_id),
                        ("invalidate", "true"),
                        ("timestamp", timestamp.as_str()),
                        ("api_key", api_key.as_str()),
                        ("signature", signature.as_str()),
                    ])
                    .send()
                    .await
                    .map_err(|error| {
                        tracing::error!(error = %error, "Cloudinary proof deletion request failed");
                        AppError::Unavailable
                    })?;
                if !response.status().is_success() {
                    tracing::error!(status = %response.status(), resource_type, "Cloudinary rejected proof deletion");
                    return Err(AppError::Unavailable);
                }
                let result = response
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|error| {
                        tracing::error!(error = %error, "invalid Cloudinary deletion response");
                        AppError::Unavailable
                    })?;
                match result["result"].as_str() {
                    Some("ok" | "not found") => Ok(()),
                    _ => {
                        tracing::error!("Cloudinary did not confirm proof deletion");
                        Err(AppError::Unavailable)
                    }
                }
            }
        }
    }
}

fn parse_cloudinary_key(key: &str) -> Result<(&str, &str), AppError> {
    let mut parts = key.split('/');
    let valid_prefix = parts.next() == Some("cloudinary");
    let resource_type = parts.next().unwrap_or_default();
    let asset_id = parts.next().unwrap_or_default();
    if !valid_prefix
        || !["image", "raw"].contains(&resource_type)
        || asset_id.is_empty()
        || parts.next().is_some()
        || !asset_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err(AppError::BadRequest("Invalid storage key"));
    }
    Ok((resource_type, asset_id))
}

#[cfg(test)]
mod tests {
    use super::parse_cloudinary_key;

    #[test]
    fn cloudinary_keys_validate_resource_and_asset_id() {
        assert_eq!(
            parse_cloudinary_key("cloudinary/image/asset-123").unwrap(),
            ("image", "asset-123")
        );
        assert!(parse_cloudinary_key("cloudinary/video/asset-123").is_err());
        assert!(parse_cloudinary_key("cloudinary/raw/../secret").is_err());
    }
}
