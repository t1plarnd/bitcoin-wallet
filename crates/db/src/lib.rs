use models::{RegisterData};
use async_trait::async_trait;
use eyre::Result;
use sqlx::{PgPool, Error as SqlxError};
use bcrypt::{hash, verify};
use tokio::task::spawn_blocking;


#[async_trait]
pub trait DbRepository: Send + Sync {
    async fn create_user(&self, data: &RegisterData) -> Result<(), eyre::Error>;
    async fn check_user(&self, data: &RegisterData) -> Result<bool, eyre::Error>; 
}

#[derive(Clone)]
pub struct PgRepository {
    pool: PgPool,
}

impl PgRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DbRepository for PgRepository {
    async fn create_user(&self, data: &RegisterData) -> Result<(), eyre::Error> {
    
        let password_to_hash = data.password.clone();

        let hashed = spawn_blocking(move || {
            hash(password_to_hash, 10) 
        })
        .await??;

        sqlx::query!(
            r#"INSERT INTO users (username, hashed_password) 
                VALUES ($1, $2)
                ON CONFLICT (username) DO NOTHING"#,
            data.username,
            hashed 
        )
        .execute(&self.pool)
        .await?;
    
        Ok(())
    }

    async fn check_user(&self, data: &RegisterData) -> Result<bool, eyre::Error> {
    
        let record = match sqlx::query!(
            r#"SELECT hashed_password FROM users WHERE username = $1"#,
            data.username
        )
        .fetch_one(&self.pool)
        .await
        {
            Ok(record) => record,
            Err(SqlxError::RowNotFound) => {
                return Ok(false);
            }
            Err(e) => {
                return Err(e.into());
            }
        };
        let provided_password = data.password.clone();
        let stored_hash = record.hashed_password;
        let is_valid = spawn_blocking(move || {
            verify(provided_password, &stored_hash)
        })
        .await??;
        Ok(is_valid)
    }

}
