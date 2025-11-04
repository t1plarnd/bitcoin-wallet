use serde::{Deserialize, Serialize};
use dotenv::dotenv;
use eyre::Result;
use std::env;


#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        dotenv().ok();
        let database_url = env::var("DATABASE_URL")?;
        let jwt_secret = env::var("JWT_STRING")?;
        Ok(Config {
            database_url,
            jwt_secret,
        })
    }
}


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String, 
    pub exp: i64,  
}


#[derive(Debug, Deserialize)]
pub struct RegisterData{
    pub username: String,
    pub password: String, 
}

