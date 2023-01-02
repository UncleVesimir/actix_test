mod common;
mod db_error;
mod services;
mod auth;
mod db;

use auth::auth::get_basic_auth_client;
use actix_web::{cookie::Key, guard, middleware::Logger, web, web::Data, App, HttpServer};
use actix_session::{SessionMiddleware, Session, storage::CookieSessionStore};
use db::db::get_pool;
use dotenv::dotenv;
use oauth2::basic::BasicClient;
use services::{echo, get_user, hello, manual_hello, new_user, ping};
use sqlx::{Pool, Postgres};

pub struct AppState {
    db: Pool<Postgres>,
    oauth: BasicClient,
}



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    let pool = get_pool().await;
    let basic_client = get_basic_auth_client();
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

        App::new()
            .wrap(logger)
            .wrap(SessionMiddleware::new(CookieSessionStore::default(), secret_key.clone()))
            .app_data(Data::new(AppState { db: pool.clone(), oauth: basic_client.clone() }))
            .service(scope)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
