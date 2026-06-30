use axum::{routing::post, Router};
use tower_http::cors::{CorsLayer, Any, AllowOrigin};
use axum::http::HeaderValue;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let origins = vec!["https://privex.dpdns.org".parse::<HeaderValue>().unwrap()];
    
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(AllowOrigin::list(origins));

    let app = Router::new()
        .route("/test", post(|| async { "Hello" }))
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:9999").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
