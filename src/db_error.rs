use actix_web::{
    error,
    HttpResponse,
    http::{header::ContentType, StatusCode}
};

use derive_more::{Display, Error};

#[derive(Display, Debug, Error)]
pub enum DBError {
    #[display(fmt= "User not found")]
    UserNotFound,
    #[display(fmt= "User deleted")]
    UserDeleted,
    #[display(fmt= "Malformed ID")]
    BadIDFormat,
    #[display(fmt= "Only admins can create users")]
    NotAdmin,
    #[display(fmt= "admin token required in creation request params")]
    NoAdminToken
}

impl error::ResponseError for DBError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            DBError::UserNotFound => StatusCode::INTERNAL_SERVER_ERROR,
            DBError::UserDeleted => StatusCode::BAD_REQUEST,
            DBError::BadIDFormat => StatusCode::BAD_REQUEST,
            DBError::NotAdmin => StatusCode::UNAUTHORIZED,
            DBError::NoAdminToken => StatusCode::UNAUTHORIZED,
        }
    }
}