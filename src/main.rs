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
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(root))
        .route("/gateway/:sender", post(handle_ccip));

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
    Path(value): Path<String>,
    Json(payload): Json<ResolveCCIPPostPayload>,
) -> (StatusCode, Json<ResolveCCIPPostResponse>) {
    info!(payload = ?payload, path = %value, "All Endpoint");

    // Decode the payload.data field
    // It is made using abi.encodeWithSelector(
    //                      IResolverService.resolve.selector,
    //                      name,
    //                      data
    // )

    // The string starts with "0x"
    // the next 4 bytes are the selector
    let selector = &payload.data[2..10];
    let name = &payload.data[10..74];
    let data = &payload.data[74..];

    info!(selector = %selector, name = %name, data = %data, "Decoded payload");

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
