use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

pub fn get_database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL variable must be set")
}

pub async fn get_pool() -> Pool<Postgres> {

    let database_url = get_database_url();

    PgPoolOptions::new()
    .max_connections(5)
    .connect(&database_url)
            .await
            .expect("Error building a db connection pool")

}
