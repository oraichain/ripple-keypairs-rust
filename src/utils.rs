use sha2::{Sha256, Sha512, Digest as Sha2Digest};

use ripemd160::{Ripemd160, Digest};

pub(super) fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
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
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().iter().as_slice()[..32].to_vec()
}
