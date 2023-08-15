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
    extract::Path,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use ethers::abi::ParamType;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::info;

use crate::resolver::functions::ResolverFunctionCall;

mod resolver;
mod utils;

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
    // info!(payload = ?payload, path = %value, "All Endpoint");

    // Decode the payload.data field
    // It is made using abi.encodeWithSelector(
    //                      IResolverService.resolve.selector,
    //                      name,
    //                      data
    // )
    // Using ethers.rs attempt an abi decode

    // let decoded_hex = hex::decode(data_without_0x).unwrap_or_else(|x| {
    //     info!(error = ?x, "Failed to decode hex");
    //     panic!("Failed to decode hex");
    // });

    // info!(data = ?decoded_hex, "Decoded hex");

    let data = payload.data.trim_start_matches("0x9061b923"); // Multicall

    let result = ethers::abi::decode(
        &[ParamType::Bytes, ParamType::Bytes],
        &hex::decode(data).unwrap(),
    )
    .unwrap();

    // info!(vars = ?result, "Decoded vars");

    // Names are encoded using DNS encoding following RFC1035
    let dns_encoded_name = result[0].clone().into_bytes().unwrap();

    let name = String::from_utf8(dns_encoded_name).unwrap();

    let name = utils::dns::decode(&name);

    info!(name = ?name, "Decoded name");

    // This payload contains an abi encoded with selector payload, the first few bytes include the function selector
    let rest_of_the_data = result[1].clone().into_bytes().unwrap();

    // info!(rest_of_the_data = ?rest_of_the_data, "Rest of the data");

    // hex encode rest of data
    // let rest_of_the_data = hex::encode(rest_of_the_data);

    // let bytes_of_hex_of_addr_func = hex::decode("f1cb7e06").unwrap();

    // info!(bytes_of_hex_of_addr_func = ?bytes_of_hex_of_addr_func, "Bytes of hex of addr func");

    // info!(rest_of_the_data = ?rest_of_the_data, "Rest of the data");

    let function_selector: &[u8; 4] = &rest_of_the_data[0..4].try_into().unwrap();

    let call = ResolverFunctionCall::try_from(function_selector).unwrap();

    info!(call = ?call, "Function call");

    let rest_of_the_data = hex::encode(rest_of_the_data);

    info!(rest_of_the_data = ?rest_of_the_data, "Rest of the data");

    // let function_selector = String::from_utf8_lossy(function_selector.into());

    // info!(function_selector = ?function_selector, "Function selector");

    // let vals = ethers::abi::decode(
    //     vec![ParamType::FixedBytes(4), ParamType::FixedBytes(10), ParamType::Bytes].as_slice(),
    //     decoded_hex.as_slice(),
    // ).unwrap();

    // let selector = vals[0].clone().into_fixed_bytes().unwrap();
    // let name = vals[1].clone().into_fixed_bytes().unwrap();
    // let data = vals[2].clone().into_bytes().unwrap();

    // info!(selector = ?selector, name = ?name, data = ?data, "Decoded payload");

    let user = ResolveCCIPPostResponse {
        data: "".to_string(),
    };

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
