use actix_web::{get, error, middleware::Logger, guard, post, web, web::{
    Data,
    Path,
    Query,
    Json
}, App, HttpResponse, HttpServer, Responder};

use std::sync::Mutex;
use serde::{Deserialize};
mod db_error;
use db_error::DBError;

struct AppStateWithCounter {
   counter: Mutex<usize>,
}

#[derive(Deserialize)]
struct Info {
    is_admin: Option<bool>
}

#[derive(Deserialize)]
struct JsonUser {
    username: String,
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello World!")
}

#[post("/echo")]
async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[get("/user/{user_id}")]
async fn get_user(path: Path<u32>, query: Query<Info>) -> Result<String, DBError> {
    let user_id = path.into_inner(); 
    if let Some(is_admin) = query.is_admin {
        match is_admin {
            true => {
                if user_id == 11 { return Err(DBError::UserDeleted) }
                else{
                    return Ok(format!("User {} exists!", user_id))
                }
            },
            false => return Err(DBError::NotAdmin),
        }
    }
    else{
        return Err(DBError::NoAdminToken);
    }
}

#[post("/user")]
async fn new_user(user: Json<JsonUser>) -> Result<Json<String>, error::Error> {
    Ok(Json(format!("New user created under username: {}", user.username)))
}

#[get("/ping")]
async fn ping(data: Data<AppStateWithCounter>) -> impl Responder {
    let mut count = data.counter.lock().unwrap();
    *count += 1;
    HttpResponse::Ok().body(format!("You've pinged this endpoint {} time(s)", count))
}

async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state_count = AppStateWithCounter {
        counter: Mutex::new(0), 
    };

    let counter = Data::new(state_count);

    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    
    HttpServer::new(move || {
            let logger = Logger::default();
            let scope = web::scope("/dunky")
                .guard(guard::Header("Host", "localhost:8080"))
                .service(hello)
                .service(echo)
                .service(ping)
                .service(get_user)
                .service(new_user)
                .route("/hey", web::get().to(manual_hello));

            App::new()
                .wrap(logger)
                .app_data(counter.clone())
                .service(scope)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}


