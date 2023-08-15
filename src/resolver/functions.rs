
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverFunctionCall {
    addr,                 // 0x3b3b57de
    name,                 // 0x691f3431
    ABI,                  // 0x2203ab56
    text,                 // 0x59d1d43c
    contenthash,          // 0xbc1c58d1
    interfaceImplementer, // 0xb8f2bbb4
    addrMultichain,       // 0xf1cb7e06
}

impl TryFrom<&[u8; 4]> for ResolverFunctionCall {
    type Error = ();

    fn try_from(bytes: &[u8; 4]) -> Result<Self, Self::Error> {
        let hex_bytes = hex::encode(bytes);

        match hex_bytes.as_str() {
            "3b3b57de" => Ok(ResolverFunctionCall::addr),
            "691f3431" => Ok(ResolverFunctionCall::name),
            "2203ab56" => Ok(ResolverFunctionCall::ABI),
            "59d1d43c" => Ok(ResolverFunctionCall::text),
            "bc1c58d1" => Ok(ResolverFunctionCall::contenthash),
            "b8f2bbb4" => Ok(ResolverFunctionCall::interfaceImplementer),
            "f1cb7e06" => Ok(ResolverFunctionCall::addrMultichain),
            _ => Err(()),
        }
    }
}
