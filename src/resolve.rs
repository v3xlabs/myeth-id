use axum::http::StatusCode;
use ethers::{
    abi::{AbiEncode, ParamType, Token},
    signers::LocalWallet,
    types::{H160, U256, U64},
    utils::keccak256,
};
use std::{env, str::FromStr};
use tracing::info;

use crate::{
    resolver::functions::ResolverFunctionCall, utils, ResolveCCIPPostPayload,
    ResolveCCIPPostResponse,
};

fn magic_data(value: Vec<u8>, sender: &H160, request_payload: String) -> String {
    let result = value;

    let request_payload = hex::decode(request_payload.trim_start_matches("0x")).unwrap();

    let expires: u64 = 1703980800;

    let request_hash = keccak256(request_payload).to_vec();
    let result_hash = keccak256(&result).to_vec();

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

    let signature_r = signature.r.encode();
    let signature_s = signature.s.encode();
    let signature_v = vec![signature.v.try_into().unwrap()];

    let signature = [signature_r, signature_s, signature_v].concat();

    format!(
        "0x{}",
        hex::encode(ethers::abi::encode(
            vec![
                Token::Bytes(result),
                Token::Uint(U256::from(expires)),
                Token::Bytes(signature),
            ]
            .as_slice()
        ))
    )
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

    let label_name = name
        .split('.')
        .next()
        .ok_or(ResolveError::DNSDecode())?
        .to_string();

    // This payload contains an abi encoded with selector payload, the first few bytes include the function selector
    let rest_of_the_data = result[1].clone().into_bytes().unwrap();

    let call = ResolverFunctionCall::try_from(rest_of_the_data.as_slice()).unwrap();

    let result = match call {
        ResolverFunctionCall::Addr(_namehash) => {
            // info!(namehash = ?namehash, "Namehash");

            let reply = H160::from_str("0x225f137127d9067788314bc7fcc1f36746a3c3B5").unwrap();

            Ok([Token::Address(reply)])
        }
        ResolverFunctionCall::Text(_namehash, record) => {
            // info!(namehash = ?namehash, record = ?record, "Namehash & Record");
            Ok([Token::String(match record.as_str() {
                "description" => Ok(format!("My name is {} and this is myeth.id", label_name)),
                "avatar" => Ok(
                    "https://media.tenor.com/SSY2V0RrU3IAAAAM/rick-roll-rick-rolled.gif"
                        .to_string(),
                ),
                "website" => Ok(format!("https://{}.myeth.id", label_name)),
                "display" => Ok(format!("{}.MyETH.ID", label_name)),
                "keywords" => Ok("myeth.id".to_string()),
                "url" => Ok("https://myeth.id".to_string()),
                "name" => Ok("myeth.id".to_string()),
                "location" => Ok("Location".to_string()),
                _ => Ok("Hello World".to_string()),
            }?)])
        }
        ResolverFunctionCall::AddrMultichain(_namehash, coin_type) => {
            info!(label_name = ?label_name, coin_type = ?coin_type, "Namehash & Coin Type");

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
