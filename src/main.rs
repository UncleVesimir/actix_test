use actix_web::{guard, middleware::Logger, web, web::Data, App, HttpServer};
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::sync::Mutex;

mod common;
mod db_error;
mod services;

use common::AppStateWithCounter;
use services::{echo, get_user, hello, manual_hello, new_user, ping};

pub struct AppState {
    db: Pool<Postgres>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?
        .expect("Error building a db connection pool");

    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    HttpServer::new(move || {
        let logger = Logger::default();
        let scope = web::scope("")
            .guard(guard::Header("Host", "localhost:8080"))
            .service(hello)
            .service(echo)
            .service(ping)
            .service(get_user)
            .service(new_user)
            .route("/hey", web::get().to(manual_hello));

        App::new()
            .wrap(logger)
            .app_data(Data::new(AppState { db: pool.clone() }))
            .service(scope)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
