mod auth_utils;

use auth_utils::{fetch_stored_oauth_request, get_basic_auth_client, store_oath_request};

use actix_session::Session;
use actix_web::{
    error::{self, Error},
    get,
    http::header,
    web, HttpResponse,
};
use oauth2::reqwest::async_http_client;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use serde::Deserialize;

use crate::AppState;

#[get("/login")]
pub async fn login(data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    let pool = &data.db;
    // Google supports Proof Key for Code Exchange (PKCE - https://oauth.net/2/pkce/).
    // Create a PKCE code verifier and SHA-256 encode it as a code challenge.

    // TODO: verify if user exists in the db by looking at the session cookie, (if the client provides one.)
    // 2. Generate and Store OAuth Request.
    // 3. Craft OAuth Login URL
    // 4. Redirect the browser to the OAuth Login URL.

    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the authorization URL to which we'll redirect the user.
    let (authorize_url, csrf_state) = get_basic_auth_client()
        .authorize_url(CsrfToken::new_random)
        // This example is requesting access to user's profile
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.email".to_string(),
        ))
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/userinfo.profile".to_string(),
        ))
        .add_scope(Scope::new("openid".to_string()))
        .set_pkce_challenge(pkce_code_challenge.clone())
        .url();

    //STORE HERE

    store_oath_request(
        pool,
        pkce_code_challenge.as_str(),
        pkce_code_verifier.secret(),
        csrf_state.secret(),
    )
    .await
    .map_err(|e| error::ErrorInternalServerError(e))?;

    //redirect user to Auth screen
    Ok(HttpResponse::Found()
        .append_header((header::LOCATION, authorize_url.to_string()))
        .finish())
}
#[get("/logout")]
pub async fn logout(session: Session) -> HttpResponse {
    //GET TOKEN FROM DB THEN...
    // let token_to_revoke: StandardRevocableToken = match token_response.refresh_token() {
    //     Some(token) => token.into(),
    //     None => token_response.access_token().into(),
    // };

    // client
    //     .revoke_token(token_to_revoke)
    //     .unwrap()
    //     .request(http_client)
    //     .expect("Failed to revoke token");
    session.remove("login");
    HttpResponse::Found()
        .append_header((header::LOCATION, "/".to_string()))
        .finish()
}

#[derive(Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
    scope: String,
}

#[get("/login/callback")]
pub async fn handle_oauth_callback(
    session: Session,
    data: web::Data<AppState>,
    params: web::Query<AuthRequest>,
) -> Result<HttpResponse, Error> {
    let pool = &data.db;
    let response_state = params.state.clone();
    let auth_code = AuthorizationCode::new(params.code.clone());
    // 1. Fetch OAuth request from db. If this fails, it's likely the Csrf Token is invalid.
    // could be malicious request of auth error.
    let stored_oauth_request = fetch_stored_oauth_request(pool, &response_state)
        .await
        .map_err(|e| {
            log::error!("{:?}", e);
            error::ErrorBadRequest("Failed to validate OAuth request")
        })?;

    let _scope = params.scope.clone();

    let client = get_basic_auth_client();
    // Build Token Request code with a token.
    let token = client
        .exchange_code(auth_code)
        .set_pkce_verifier(PkceCodeVerifier::new(stored_oauth_request.pkce_verifier))
        .request_async(async_http_client)
        .await
        .map_err(|_e| error::ErrorBadRequest("Failed to retrieve access token"))?;

    println!("{:?}", token);

    session.insert("login", true).unwrap();

    Ok(HttpResponse::Ok().body("Login Successful"))
}
