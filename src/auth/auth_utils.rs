use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

use sqlx::{self, Error, Pool, Postgres};
use std::env;

#[derive(sqlx::FromRow)]
pub struct OAuthRequest {
    pub pkce_challenge: String,
    pub pkce_verifier: String,
    pub csrf_state: String,
}

pub async fn store_oath_request(
    pool: &Pool<Postgres>,
    pkce_challenge: &str,
    pkce_verifier: &str,
    csrf_state: &str,
) -> Result<(), Error> {
    sqlx::query(
        "
      INSERT INTO oauth_requests (pkce_challenge, pkce_verifier, csrf_state)
        VALUES ($1, $2, $3)",
    )
    .bind(pkce_challenge)
    .bind(pkce_verifier)
    .bind(csrf_state)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn fetch_stored_oauth_request(
    pool: &Pool<Postgres>,
    response_state: &String,
) -> Result<OAuthRequest, Error> {
    sqlx::query_as::<_, OAuthRequest>(
        "
    SELECT * FROM oauth_requests WHERE csrf_state=$1
  ",
    )
    .bind(response_state)
    .fetch_one(pool)
    .await
}

pub fn get_basic_auth_client() -> BasicClient {
    //assumes you've set env variables
    let google_client_id = ClientId::new(
        env::var("GOOGLE_OAUTH_CLIENT_ID")
            .expect("Missing the GOOGLE_CLIENT_ID environment variable."),
    );
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_OAUTH_CLIENT_SECRET")
            .expect("Missing the GOOGLE_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(
        RedirectUrl::new("http://localhost:8080/auth/login/callback".to_string())
            .expect("Invalid redirect URL"),
    )
}
