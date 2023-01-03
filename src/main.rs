mod auth;
mod common;
mod db;
mod db_error;
mod services;

// use actix_cors::Cors;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, guard, middleware::Logger, web, web::Data, App, HttpServer};
use auth::{handle_oauth_callback, login, logout};
use db::db::get_pool;
use dotenv::dotenv;
use services::{echo, get_user, hello, manual_hello, new_user, ping};
use sqlx::{Pool, Postgres};

pub struct AppState {
    db: Pool<Postgres>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    let pool = get_pool().await;
    let secret_key = Key::generate();

    HttpServer::new(move || {
        let logger = Logger::default();
        let scope = web::scope("")
            .guard(guard::Header("Host", "localhost:8080"))
            //authmiddleware here
            .service(hello)
            .service(echo)
            .service(ping)
            .service(get_user)
            .service(new_user)
            .route("/hey", web::get().to(manual_hello));

        let auth_scope = web::scope("/auth")
            .guard(guard::Header("Host", "localhost:8080"))
            //authmiddleware here
            .service(login)
            .service(logout)
            .service(handle_oauth_callback);

        App::new()
            .wrap(logger)
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                secret_key.clone(),
            ))
            .app_data(Data::new(AppState { db: pool.clone() }))
            .service(auth_scope)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
