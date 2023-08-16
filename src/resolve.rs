use axum::{
    extract::Path,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use ethers::{
    abi::{AbiEncode, ParamType, Token},
    signers::LocalWallet,
    types::{Signature, H160, U256, U64},
    utils::keccak256,
};
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr, str::FromStr};
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::{
    resolver::functions::ResolverFunctionCall, utils, ResolveCCIPPostPayload,
    ResolveCCIPPostResponse,
};

fn magic_data(value: Vec<u8>, sender: &H160, request_payload: String) -> String {
    let result = value;
    let result_as_utf8_str = hex::encode(&result);

    info!(result = ?result, "Result");
    info!(result_as_utf8_str = ?result_as_utf8_str, "Result as UTF8 Str");
    let request_payload = hex::decode(request_payload.trim_start_matches("0x")).unwrap();
    info!(request_payload = ?request_payload, "Request Payload");

    let expires: u64 = 1693140299;

    let request_hash = keccak256(request_payload).to_vec();
    let result_hash = keccak256(&result).to_vec();

    info!("Sender: {:?}", sender);
    info!("Expires: {:?}", expires);
    info!("Request Hash: {:?}", request_hash);
    info!("Result Hash: {:?}", result_hash);

    // Hash and sign the response
    let encoded = ethers::abi::encode_packed(&[
        Token::Uint(U256::from(0x1900)),
        Token::Address(*sender),
        Token::FixedBytes(U64::from(expires).0[0].to_be_bytes().to_vec()),
        Token::FixedBytes(request_hash),
        Token::FixedBytes(result_hash),
    ])
    .unwrap();
    let message_hash = keccak256(encoded);

    let wallet = LocalWallet::from_str(env::var("PRIVATE_KEY").unwrap().as_str()).unwrap();
    let signature: ethers::types::Signature = wallet.sign_hash(message_hash.into()).unwrap();

    // these need padleft of 0 if less then 32 bytes
    let signature_r = signature.r.encode();
    let signature_s = signature.s.encode();
    let signature_v = vec![signature.v.try_into().unwrap()];

    info!(signature_r = ?signature_r, signature_s = ?signature_s, signature_v = ?signature_v, "Signature");

    let signature = [signature_r, signature_s, signature_v].concat();

    let data: Vec<Token> = vec![
        Token::Bytes(result),
        Token::Uint(U256::from(expires)),
        Token::Bytes(signature),
    ];

    let data = ethers::abi::encode(data.as_slice());

    let data = hex::encode(data);
    let data = format!("0x{}", data);

    data
}

#[derive(Debug)]
pub enum ResolveError {
    UnknownFunction(),
    UnknownResolverFunction(),
    ABIDecode(),
    DNSDecode(),
    NotFound(),
}

impl From<ResolveError> for StatusCode {
    fn from(val: ResolveError) -> Self {
        match val {
            ResolveError::UnknownFunction() => StatusCode::NOT_IMPLEMENTED,
            ResolveError::UnknownResolverFunction() => StatusCode::NOT_IMPLEMENTED,
            ResolveError::ABIDecode() => StatusCode::BAD_REQUEST,
            ResolveError::DNSDecode() => StatusCode::BAD_REQUEST,
            ResolveError::NotFound() => StatusCode::NOT_FOUND,
        }
    }
}

pub fn resolve(
    request_payload: ResolveCCIPPostPayload,
) -> Result<ResolveCCIPPostResponse, ResolveError> {
    // remove the 0x9061b923 at the beginning of request_payload.data otherwise throw error
    let data = request_payload
        .data
        .strip_prefix("0x9061b923")
        .ok_or(ResolveError::UnknownFunction())?;

    let result = ethers::abi::decode(
        &[ParamType::Bytes, ParamType::Bytes],
        &hex::decode(data).unwrap(),
    )
    .ok()
    .ok_or(ResolveError::ABIDecode())?;

    // Names are encoded using DNS encoding following RFC1035
    let dns_encoded_name = result[0]
        .clone()
        .into_bytes()
        .ok_or(ResolveError::DNSDecode())?;

    let name = String::from_utf8(dns_encoded_name).or(Err(ResolveError::DNSDecode()))?;

    let name = utils::dns::decode(&name);

    info!(name = ?name, "Decoded name");

    let labelname = name
        .split(".")
        .next()
        .ok_or(ResolveError::DNSDecode())?
        .to_string();

    // This payload contains an abi encoded with selector payload, the first few bytes include the function selector
    let rest_of_the_data = result[1].clone().into_bytes().unwrap();

    let call = ResolverFunctionCall::try_from(rest_of_the_data.as_slice()).unwrap();

    let result = match call {
        ResolverFunctionCall::Addr(namehash) => {
            // info!(namehash = ?namehash, "Namehash");

            let reply = H160::from_str("0x225f137127d9067788314bc7fcc1f36746a3c3B5").unwrap();

            Ok([Token::Address(reply)])
        }
        ResolverFunctionCall::Text(namehash, record) => {
            // info!(namehash = ?namehash, record = ?record, "Namehash & Record");
            Ok([Token::String(match record.as_str() {
                "description" => Ok(format!("My name is {} and this is myeth.id", labelname)),
                "avatar" => Ok(
                    "https://media.tenor.com/SSY2V0RrU3IAAAAM/rick-roll-rick-rolled.gif"
                        .to_string(),
                ),
                "url" => Ok("https://myeth.id".to_string()),
                "name" => Ok("myeth.id".to_string()),
                "location" => Ok("Location".to_string()),
                _ => Ok("Hello World".to_string()),
            }?)])
        }
        ResolverFunctionCall::AddrMultichain(namehash, coin_type) => {
            // Ok([Token::String("Hello World".to_string())])
            Err(ResolveError::NotFound())
        }
        _ => Err(ResolveError::UnknownResolverFunction()),
    }?;

    Ok(ResolveCCIPPostResponse {
        data: magic_data(
            ethers::abi::encode(&result),
            &H160::from_str(request_payload.sender.as_str()).unwrap(),
            request_payload.data,
        ),
    })
}
