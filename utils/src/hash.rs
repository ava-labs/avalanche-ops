use ring::digest::{digest, SHA256};

pub fn compute_sha256(input: &[u8]) -> Vec<u8> {
    digest(&SHA256, input).as_ref().into()
}
