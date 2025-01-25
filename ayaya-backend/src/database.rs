static DB: std::sync::OnceLock<sqlx::PgPool> = std::sync::OnceLock::new();

pub async fn init_db() {
    let pool =
        sqlx::PgPool::connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL is missing"))
            .await
            .expect("create pool");
    let _ = DB.set(pool);
}

pub fn get_db<'a>() -> &'a sqlx::PgPool {
    DB.get().expect("database unitialized")
}
