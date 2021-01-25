use ring::digest::{digest, SHA256, SHA512};

use ripemd160::{Digest, Ripemd160};

pub(super) fn sha256_digest(data: &[u8]) -> Vec<u8> {
    digest(&SHA256, data).as_ref().to_vec()
}

fn ripemd160_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().as_slice().into()
}

pub(super) fn hash160(data: &[u8]) -> Vec<u8> {
    ripemd160_digest(&sha256_digest(data))
}

pub(super) fn sha512_digest_32(data: &[u8]) -> Vec<u8> {
    digest(&SHA512, data).as_ref()[..32].to_vec()
}
