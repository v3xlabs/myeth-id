use axum::{
    extract::Path,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{AppendHeaders, Response},
    routing::{get, post},
    Json, Router,
};
use log::error;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tracing::info;

mod resolve;
mod resolver;
mod utils;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(root))
        .route("/gateway/:sender", post(handle_ccip))
        .route("/test/image", get(handle_test_image))
        .layer(CorsLayer::very_permissive());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root() -> &'static str {
    "myeth.id v0.0.1"
}

async fn handle_ccip(
    Path(sender): Path<String>,
    Json(request_payload): Json<ResolveCCIPPostPayload>,
) -> (StatusCode, Json<ResolveCCIPPostResponse>) {
    // info!("Received request from {}", sender);

    match resolve::resolve(request_payload) {
        Ok(x) => (StatusCode::OK, Json(x)),
        Err(e) => {
            error!("Error: {:?}", e);
            (e.into(), Json(ResolveCCIPPostResponse::default()))
        }
    }
}

async fn handle_test_image(headers: HeaderMap) -> &'static str {
    info!("Received request from {:?}", headers);

    ""
}

#[derive(Deserialize, Debug)]
pub struct ResolveCCIPPostPayload {
    data: String,
    sender: String,
}

#[derive(Serialize)]
pub struct ResolveCCIPPostResponse {
    data: String,
}

#[derive(Serialize)]
struct ResolveCCIPPostErrorResponse {
    message: String,
}

impl Default for ResolveCCIPPostResponse {
    fn default() -> Self {
        Self {
            data: "0x".to_string(),
        }
    }
}
