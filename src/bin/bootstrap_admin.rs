use argon2::{ password_hash::{ rand_core::OsRng, PasswordHasher, SaltString }, Argon2 };
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let database_url = std::env::var("DATABASE_URL")?;
    let email = std::env::var("BOOTSTRAP_ADMIN_EMAIL")?;
    let full_name = std::env::var("BOOTSTRAP_ADMIN_NAME")?;
    let password = std::env::var("BOOTSTRAP_ADMIN_PASSWORD")?;
    anyhow::ensure!(
        password.len() >= 12 && password.len() <= 128,
        "BOOTSTRAP_ADMIN_PASSWORD must be 12–128 bytes"
    );
    anyhow::ensure!(
        email.contains('@') && email.len() <= 254,
        "BOOTSTRAP_ADMIN_EMAIL must be valid"
    );
    anyhow::ensure!(!full_name.trim().is_empty(), "BOOTSTRAP_ADMIN_NAME is required");

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string();
    let db = PgPoolOptions::new().max_connections(5).connect(&database_url).await?;
    let email_normalized = email.trim().to_lowercase();
    let mut tx = db.begin().await?;
    let id: uuid::Uuid = sqlx
        ::query_scalar(
            "INSERT INTO users(email,email_normalized,password_hash,full_name,email_verified_at) VALUES ($1,$2,$3,$4,now()) RETURNING id"
        )
        .bind(email.trim())
        .bind(&email_normalized)
        .bind(password_hash)
        .bind(full_name.trim())
        .fetch_one(&mut *tx).await?;
    sqlx
        ::query("INSERT INTO user_roles(user_id,role_code) VALUES ($1,'admin')")
        .bind(id)
        .execute(&mut *tx).await?;
    sqlx
        ::query(
            "INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES ($1,'admin.bootstrap','user',$1,'{}'::jsonb)"
        )
        .bind(id)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    println!("Initial Scried admin created for {}. Remove BOOTSTRAP_ADMIN_PASSWORD from your environment.", email_normalized);
    Ok(())
}
