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
use ethers::{
    abi::{AbiEncode, ParamType, Token},
    signers::LocalWallet,
    types::{H160, U256},
};
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr, str::FromStr};
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::resolver::functions::ResolverFunctionCall;

mod resolver;
mod utils;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(root))
        .route("/gateway/:sender", post(handle_ccip))
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
    Path(value): Path<String>,
    Json(request_payload): Json<ResolveCCIPPostPayload>,
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

    let data = request_payload.data.trim_start_matches("0x9061b923"); // Multicall

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

    // let rest_of_the_data = hex::encode(rest_of_the_data);

    // info!(rest_of_the_data = ?rest_of_the_data, "Rest of the data");

    // let rest_of_data = hex_literal::hex!(
    //     "3b3b57ded379bcd305d2f206378661c8f0d1ca3a2c9072a898c8d23ed4406fd965264dbd"
    // );

    // 59d1d43cd379bcd305d2f206378661c8f0d1ca3a2c9072a898c8d23ed4406fd965264dbd000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000086c6f636174696f6e000000000000000000000000000000000000000000000000
    // 3b3b57ded379bcd305d2f206378661c8f0d1ca3a2c9072a898c8d23ed4406fd965264dbd
    // 59d1d43cd379bcd305d2f206378661c8f0d1ca3a2c9072a898c8d23ed4406fd965264dbd000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000046e616d6500000000000000000000000000000000000000000000000000000000
    // 59d1d43cd379bcd305d2f206378661c8f0d1ca3a2c9072a898c8d23ed4406fd965264dbd0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000b6465736372697074696f6e0000000

    // get the rest of data except for the first 4 bytes
    let payload = rest_of_the_data[4..].to_vec();

    if call == ResolverFunctionCall::addr {
        info!("ADDR Call");

        let result = ethers::abi::decode(&[ParamType::FixedBytes(32)], &payload).unwrap();
        let namehash = result[0].clone().into_fixed_bytes().unwrap();

        info!(namehash = ?namehash, "Namehash");

        // 0x prefixed hex string containing the result data
        // let data = "0x225f137127d9067788314bc7fcc1f36746a3c3B5";
        // 0x000000000000000000000000000000000000000000000000000000000000006
        //   00000000000000000000000000000000000000000000000000000000064dbfb1b00000000000000000000000000000000000000000000000000000000000000c
        //   00000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000002
        //   00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004
        //   160c26e8778324cd0d3ff04f57418b79efc07f2f87085d8fd32439d748cdfd8a9164b477ef66ce48d742ae5075cee9a16342c31074d00941b3213a11006f71f7e1b00000000000000000000000000000000000000000000000000000000000000

        // let to_address = data;
        // let valid_until = 3600;
        // let keccak_of_request_data =
        // let keccak_of_response_data =

        // Solidity Keccak256 ['bytes', 'address', 'uint64', 'bytes32', 'bytes32']
        // 0x1900 request.to validUntil

        // messageHash = solidityKeccak256(
        //   ['bytes', 'address', 'uint64', 'bytes32', 'bytes32'],
        //   [
        //     '0x1900', to, validUntil, keccak256(requestData || '0x'), keccak256(responseData)
        // ]
        // )
        // sig = signer.signDigest(messageHash);
        // signature_data = hexConcat([sig.r, sig._vs])
        // result, valid until, signature_data

        let address = H160::from_str("0x225f137127d9067788314bc7fcc1f36746a3c3B5").unwrap();
        // Result is the address but leftpadded with zeroes to 32 bytes in length
        let result = address.encode();
        info!(result = ?result, "Result");

        let expires: u64 = 1693140299;
        let expires: U256 = expires.into();

        let payload_data_bytes =
            hex::decode(request_payload.data.strip_prefix("0x").unwrap()).unwrap();

        let request_hash = ethers::utils::keccak256(payload_data_bytes).to_vec();
        let result_hash = ethers::utils::keccak256(address).to_vec();

        let sender = H160::from_str(&request_payload.sender).unwrap();

        let payload_hash = ethers::abi::encode_packed(
            vec![
                Token::Bytes(hex::decode("1900").unwrap()),
                Token::Address(sender),
                Token::Uint(expires),
                Token::Bytes(request_hash),
                Token::Bytes(result_hash),
            ]
            .as_slice(),
        )
        .unwrap();

        let payload_hash = ethers::utils::keccak256(payload_hash);

        let wallet = LocalWallet::from_str(env::var("PRIVATE_KEY").unwrap().as_str()).unwrap();
        let signature = wallet.sign_hash(payload_hash.into()).unwrap();

        // TODO: Figure out hexConcat, (to_string atm)
        let signature_r = format!("{:02x}", signature.r);
        let signature_s = format!("{:02x}", signature.s);
        let signature_v = format!("{:02x}", signature.v);

        info!(signature_r = ?signature_r, signature_s = ?signature_s, signature_v = ?signature_v, "Signature");

        let signature = hex::decode(format!("{}{}{}", signature_r, signature_s, signature_v))
            .unwrap()
            .to_vec();

        let data = vec![
            Token::Bytes(result),
            Token::Uint(expires),
            Token::Bytes(signature),
        ];

        let data = ethers::abi::encode(data.as_slice());

        let data = hex::encode(data);
        let data = format!("0x{}", data);

        return (StatusCode::OK, Json(ResolveCCIPPostResponse { data }));
    }

    if call == ResolverFunctionCall::text {
        info!("CONTENT Call");

        let result = ethers::abi::decode(&[ParamType::FixedBytes(32), ParamType::String], &payload).unwrap();
        let namehash = result[0].clone().into_fixed_bytes().unwrap();
        let record = result[1].clone().into_string().unwrap();

        info!(namehash = ?namehash, record = ?record, "Namehash & Record");

        let value = "Hello World";
        // Result is the address but leftpadded with zeroes to 32 bytes in length
        let result = value.encode();
        info!(result = ?result, "Result");

        let expires: u64 = 1693140299;
        let expires: U256 = expires.into();

        let payload_data_bytes =
            hex::decode(request_payload.data.strip_prefix("0x").unwrap()).unwrap();

        let request_hash = ethers::utils::keccak256(payload_data_bytes).to_vec();
        let result_hash = ethers::utils::keccak256(value).to_vec();

        let sender = H160::from_str(&request_payload.sender).unwrap();

        let payload_hash = ethers::abi::encode_packed(
            vec![
                Token::Bytes(hex::decode("1900").unwrap()),
                Token::Address(sender),
                Token::Uint(expires),
                Token::Bytes(request_hash),
                Token::Bytes(result_hash),
            ]
            .as_slice(),
        )
        .unwrap();

        let payload_hash = ethers::utils::keccak256(payload_hash);

        let wallet = LocalWallet::from_str(env::var("PRIVATE_KEY").unwrap().as_str()).unwrap();
        let signature = wallet.sign_hash(payload_hash.into()).unwrap();

        // TODO: Figure out hexConcat, (to_string atm)
        let signature_r = format!("{:02x}", signature.r);
        let signature_s = format!("{:02x}", signature.s);
        let signature_v = format!("{:02x}", signature.v);

        info!(signature_r = ?signature_r, signature_s = ?signature_s, signature_v = ?signature_v, "Signature");

        let signature = hex::decode(format!("{}{}{}", signature_r, signature_s, signature_v))
            .unwrap()
            .to_vec();

        let data = vec![
            Token::Bytes(result),
            Token::Uint(expires),
            Token::Bytes(signature),
        ];

        let data = ethers::abi::encode(data.as_slice());

        let data = hex::encode(data);
        let data = format!("0x{}", data);

        return (StatusCode::OK, Json(ResolveCCIPPostResponse { data }));
    }

    let user = ResolveCCIPPostResponse {
        data: "0x".to_string(),
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
