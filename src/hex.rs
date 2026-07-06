pub(crate) fn decode(hex: &str) -> Result<Vec<u8>, faster_hex::Error> {
    let mut bytes = vec![0; hex.len() / 2];
    faster_hex::hex_decode(hex.as_bytes(), &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = vec![0; bytes.len() * 2];
    faster_hex::hex_encode(bytes, &mut out).expect("hex output buffer is exactly twice the input length");
    String::from_utf8(out).expect("faster-hex emits ASCII hex")
}
