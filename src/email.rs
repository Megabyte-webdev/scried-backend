use crate::config::EmailConfig;
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::time::Duration;
use url::Url;
use uuid::Uuid;

const BATCH_SIZE: i64 = 1;
const CLAIM_LEASE_SECONDS: i64 = 180;

pub struct EmailDeliveryWorker {
    config: EmailConfig,
    http: reqwest::Client,
    smtp: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

struct OutboxMessage {
    id: Uuid,
    recipient: String,
    template: String,
    payload: Value,
    attempts: i32,
}

struct PreparedEmail {
    subject: String,
    body: String,
}

#[derive(Deserialize)]
struct ResendErrorResponse {
    message: Option<String>,
}

impl EmailDeliveryWorker {
    pub fn new(config: EmailConfig) -> anyhow::Result<Self> {
        let from = config.from.parse::<Mailbox>()?;
        let smtp = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)?
            .port(config.smtp_port)
            .credentials(Credentials::new(
                config.smtp_username.clone(),
                config.smtp_password.clone(),
            ))
            .timeout(Some(Duration::from_secs(30)))
            .build();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            config,
            http,
            smtp,
            from,
        })
    }

    pub async fn run(self, db: PgPool) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            match self.process_batch(&db).await {
                Ok(0) => {}
                Ok(count) => tracing::debug!(processed = count, "email outbox batch processed"),
                Err(error) => tracing::error!(error = %error, "email outbox worker failed"),
            }
        }
    }

    async fn process_batch(&self, db: &PgPool) -> anyhow::Result<usize> {
        let messages = claim_batch(db).await?;
        let count = messages.len();
        for message in messages {
            match self.deliver(&message).await {
                Ok(()) => {
                    sqlx::query("UPDATE email_outbox SET sent_at=now(),payload='{}'::jsonb,last_error=NULL WHERE id=$1 AND sent_at IS NULL")
                        .bind(message.id)
                        .execute(db)
                        .await?;
                    tracing::info!(message_id = %message.id, template = %message.template, "outbox email sent");
                }
                Err(error) => {
                    let delay_seconds = retry_delay_seconds(message.attempts);
                    sqlx::query("UPDATE email_outbox SET available_at=now()+($2::bigint * interval '1 second'),last_error=$3 WHERE id=$1 AND sent_at IS NULL")
                        .bind(message.id)
                        .bind(delay_seconds)
                        .bind(error.to_string())
                        .execute(db)
                        .await?;
                    tracing::error!(
                        message_id = %message.id,
                        template = %message.template,
                        attempt = message.attempts,
                        retry_in_seconds = delay_seconds,
                        error = %error,
                        "outbox email delivery failed"
                    );
                }
            }
        }
        Ok(count)
    }

    async fn deliver(&self, message: &OutboxMessage) -> anyhow::Result<()> {
        let email = prepare_email(message, &self.config.frontend_base_url)?;
        let Some(resend_api_key) = self.config.resend_api_key.as_deref() else {
            tracing::debug!(
                message_id = %message.id,
                "Resend is not configured; sending email through SMTP"
            );
            return self.send_smtp(message, &email).await;
        };

        match self.send_resend(message, &email, resend_api_key).await {
            Ok(()) => Ok(()),
            Err(error) if error.rate_or_quota_limited => {
                tracing::warn!(
                    message_id = %message.id,
                    "Resend rejected the email due to a rate or quota limit; trying SMTP fallback"
                );
                self.send_smtp(message, &email).await
            }
            Err(error) => Err(anyhow::anyhow!("Resend delivery failed: {}", error.message)),
        }
    }

    async fn send_resend(
        &self,
        message: &OutboxMessage,
        email: &PreparedEmail,
        api_key: &str,
    ) -> Result<(), ResendFailure> {
        let response = self
            .http
            .post("https://api.resend.com/emails")
            .bearer_auth(api_key)
            .header("Idempotency-Key", message.id.to_string())
            .json(&serde_json::json!({
                "from": self.config.from,
                "to": [message.recipient],
                "subject": email.subject,
                "text": email.body,
            }))
            .send()
            .await
            .map_err(|error| ResendFailure {
                message: error.to_string(),
                rate_or_quota_limited: false,
            })?;

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        let body = response.text().await.map_err(|error| ResendFailure {
            message: format!("HTTP {status}; unable to read provider error response: {error}"),
            rate_or_quota_limited: false,
        })?;
        let provider_message = serde_json::from_str::<ResendErrorResponse>(&body)
            .ok()
            .and_then(|response| response.message)
            .unwrap_or_else(|| format!("HTTP {status}"));
        let rate_or_quota_limited = is_rate_or_quota_limited(status.as_u16(), &provider_message);

        Err(ResendFailure {
            message: provider_message,
            rate_or_quota_limited,
        })
    }

    async fn send_smtp(
        &self,
        message: &OutboxMessage,
        email: &PreparedEmail,
    ) -> anyhow::Result<()> {
        let recipient = message.recipient.parse::<Mailbox>()?;
        let mail = Message::builder()
            .from(self.from.clone())
            .to(recipient)
            .subject(&email.subject)
            .header(ContentType::TEXT_PLAIN)
            .body(email.body.clone())?;
        self.smtp.send(mail).await?;
        Ok(())
    }
}

struct ResendFailure {
    message: String,
    rate_or_quota_limited: bool,
}

fn is_rate_or_quota_limited(status: u16, message: &str) -> bool {
    let lower_message = message.to_ascii_lowercase();
    let indicates_limit = lower_message.contains("quota")
        || lower_message.contains("rate limit")
        || (lower_message.contains("limit")
            && ["reach", "exceed", "maximum"]
                .iter()
                .any(|word| lower_message.contains(word)));
    status == 429 || ((status == 402 || status == 403) && indicates_limit)
}

async fn claim_batch(db: &PgPool) -> anyhow::Result<Vec<OutboxMessage>> {
    let rows = sqlx::query(
        "WITH candidates AS (
            SELECT id FROM email_outbox
            WHERE sent_at IS NULL AND available_at <= now()
            ORDER BY created_at
            LIMIT $1
            FOR UPDATE SKIP LOCKED
        )
        UPDATE email_outbox AS outbox
        SET attempts=outbox.attempts+1,
            available_at=now()+($2::bigint * interval '1 second')
        FROM candidates
        WHERE outbox.id=candidates.id
        RETURNING outbox.id,outbox.recipient,outbox.template,outbox.payload,outbox.attempts",
    )
    .bind(BATCH_SIZE)
    .bind(CLAIM_LEASE_SECONDS)
    .fetch_all(db)
    .await?;

    rows.into_iter()
        .map(|row| {
            Ok(OutboxMessage {
                id: row.try_get("id")?,
                recipient: row.try_get("recipient")?,
                template: row.try_get("template")?,
                payload: row.try_get("payload")?,
                attempts: row.try_get("attempts")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(Into::into)
}

fn prepare_email(
    message: &OutboxMessage,
    frontend_base_url: &Url,
) -> anyhow::Result<PreparedEmail> {
    let token = message
        .payload
        .get("token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("outbox payload is missing its token"))?;
    let (path, subject, action, expiry) = match message.template.as_str() {
        "verify_email" => (
            "verify-email",
            "Verify your Scried email address",
            "verify your email address",
            "This link expires in 24 hours.",
        ),
        "password_reset" => (
            "reset-password",
            "Reset your Scried password",
            "reset your password",
            "This link expires in 20 minutes.",
        ),
        _ => anyhow::bail!("unsupported email template"),
    };

    let mut link = frontend_base_url.join(path)?;
    link.query_pairs_mut().append_pair("token", token);

    Ok(PreparedEmail {
        subject: subject.to_string(),
        body: format!(
            "Hello,\n\nUse the link below to {action} for your Scried account:\n\n{link}\n\n{expiry}\n\nIf you did not request this, you can ignore this email.\n\nScried"
        ),
    })
}

fn retry_delay_seconds(attempts: i32) -> i64 {
    let exponent = attempts.saturating_sub(1).clamp(0, 10) as u32;
    (30_i64 * 2_i64.pow(exponent)).min(6 * 60 * 60)
}

#[cfg(test)]
mod tests {
    use super::{is_rate_or_quota_limited, prepare_email, retry_delay_seconds, OutboxMessage};
    use serde_json::json;
    use url::Url;
    use uuid::Uuid;

    #[test]
    fn verification_email_has_frontend_link_and_expiry() {
        let message = OutboxMessage {
            id: Uuid::new_v4(),
            recipient: "student@example.com".to_string(),
            template: "verify_email".to_string(),
            payload: json!({"token":"secret-token"}),
            attempts: 1,
        };
        let base_url = Url::parse("https://scried.example/").expect("valid base URL");
        let email = prepare_email(&message, &base_url).expect("email is rendered");

        assert!(email.body.contains("https://scried.example/verify-email?"));
        assert!(email.body.contains("token=secret-token"));
        assert!(!email.body.contains("user_id"));
        assert!(email.body.contains("expires in 24 hours"));
    }

    #[test]
    fn password_reset_email_uses_shorter_expiry() {
        let message = OutboxMessage {
            id: Uuid::new_v4(),
            recipient: "student@example.com".to_string(),
            template: "password_reset".to_string(),
            payload: json!({"token":"reset-token"}),
            attempts: 1,
        };
        let base_url = Url::parse("https://scried.example/").expect("valid base URL");
        let email = prepare_email(&message, &base_url).expect("email is rendered");

        assert!(email.body.contains("/reset-password?"));
        assert!(email.body.contains("expires in 20 minutes"));
    }

    #[test]
    fn retry_delay_is_exponential_and_capped() {
        assert_eq!(retry_delay_seconds(1), 30);
        assert_eq!(retry_delay_seconds(2), 60);
        assert_eq!(retry_delay_seconds(100), 6 * 60 * 60);
    }

    #[test]
    fn smtp_fallback_is_limited_to_explicit_resend_throttling() {
        assert!(is_rate_or_quota_limited(429, "Too many requests"));
        assert!(is_rate_or_quota_limited(
            403,
            "You reached your daily sending limit"
        ));
        assert!(is_rate_or_quota_limited(402, "Monthly quota exceeded"));
        assert!(!is_rate_or_quota_limited(403, "Invalid API key"));
        assert!(!is_rate_or_quota_limited(500, "Quota exceeded"));
    }
}
