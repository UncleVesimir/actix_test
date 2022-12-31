use actix_web::{
    error, get, post,
    web::{Data, Json, Path, Query},
    HttpResponse, Responder,
};

use super::common::AppStateWithCounter;
use super::db_error::DBError;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Info {
    is_admin: Option<bool>,
}

#[derive(Deserialize)]
pub struct JsonUser {
    username: String,
}

#[get("/")]
pub async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello World!")
}

#[post("/echo")]
pub async fn echo(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

#[get("/user/{user_id}")]
pub async fn get_user(path: Path<u32>, query: Query<Info>) -> Result<String, DBError> {
    let user_id = path.into_inner();
    if let Some(is_admin) = query.is_admin {
        match is_admin {
            true => {
                if user_id == 11 {
                    return Err(DBError::UserDeleted);
                } else {
                    return Ok(format!("User {} exists!", user_id));
                }
            }
            false => return Err(DBError::NotAdmin),
        }
    } else {
        return Err(DBError::NoAdminToken);
    }
}

#[post("/user")]
pub async fn new_user(user: Json<JsonUser>) -> Result<Json<String>, error::Error> {
    Ok(Json(format!(
        "New user created under username: {}",
        user.username
    )))
}

#[get("/ping")]
pub async fn ping(data: Data<AppStateWithCounter>) -> impl Responder {
    let mut count = data.counter.lock().unwrap();
    *count += 1;
    HttpResponse::Ok().body(format!("You've pinged this endpoint {} time(s)", count))
}

pub async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}
