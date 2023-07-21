use hmac::{Hmac, Mac};
use ripemd::{Ripemd160, Ripemd160Core};
use sha2::{Sha256, Sha512};

use tiny_keccak::{keccakf, Hasher, Keccak, Sha3};

use crate::sha2::Digest;

type HmacSha512 = Hmac<Sha512>;

pub fn hmac_sha512(seed_hex: &str) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice("Bitcoin seed".as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(&hex::decode(seed_hex).expect("invalid hex string"));

    let result = mac.finalize();
    result.into_bytes().to_vec()
    // hex::encode(bytes_data)
}

pub fn hmac_sha512_p2(chain_code: Vec<u8>, key: Vec<u8>) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice(&chain_code).expect("HMAC can take key of any size");
    mac.update(&key);
    let result = mac.finalize();
    result.into_bytes().to_vec()
    // hex::encode(bytes_data)
}

pub fn hash160(data: Vec<u8>) -> Vec<u8> {
    let mut sha_256 = Sha256::new();
    sha_256.update(&data);
    let out = sha_256.finalize();
    //
    let mut rip: Ripemd160 = Ripemd160::new();
    rip.update(&out[..]);
    let rip_rt = rip.finalize();
    rip_rt.to_vec()
}

pub fn hash_keccake256(data: Vec<u8>) -> Vec<u8> {
    let mut output = [0; 32];
    let mut sha3 = Keccak::v256();
    sha3.update(data.as_slice());
    sha3.finalize(&mut output);
    output.to_vec()
}

pub fn hash_sha256(data: Vec<u8>) -> Vec<u8> {
    let mut s = Sha256::new();

    s.update(data);
    s.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use crate::bip32::bip32::Bip32;
    use crate::bip39::bip39::mnemonic_to_seed;
    use crate::utils::hash512::hmac_sha512;

    #[test]
    fn it_test_to_base58() {
        let a: u32 = 255;
        println!("{:?}", a.to_be_bytes())
    }
}
