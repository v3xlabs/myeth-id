// use ethers::signers::LocalWallet;
// use ethers::signers::Signer;

// fn main() {
//     println!("Hello, world!");

//     // Load environment variables w dotenvy
//     // Load PRIVATE_KEY
//     // Create a Local Wallet with PRIVATE_KEY
//     // Log the address of the wallet

//     dotenvy::dotenv().ok();

//     let private_key = dotenvy::var("PRIVATE_KEY").expect("PRIVATE_KEY is not set");

//     let wallet: LocalWallet = LocalWallet::from_bytes(&hex::decode(private_key).unwrap()).unwrap();

//     println!("Wallet address: {:?}", wallet.address());
// }

use axum::{
    routing::{get, post},
    http::StatusCode,
    Json, Router, extract::Path,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        // `POST /users` goes to `create_user`
        .route("/*value", post(create_user));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// basic handler that responds with a static string
async fn root() -> &'static str {
    info!("x");

    "Hello, World!"
}

async fn create_user(
    Path(value): Path<String>,
    Json(payload): Json<ResolveCCIPPostPayload>,
) -> (StatusCode, Json<ResolveCCIPPostResponse>) {
    info!(payload = ?payload, path = %value, "All Endpoint");

    let user = ResolveCCIPPostResponse { data: "".to_string() };

    (StatusCode::CREATED, Json(user))
}

#[derive(Deserialize, Debug)]
struct ResolveCCIPPostPayload {
    data: String,
    sender: String,
}

#[derive(Serialize)]
struct ResolveCCIPPostResponse {
    data: String,
}

#[derive(Serialize)]
struct ResolveCCIPPostErrorResponse {
    message: String,
}
