use std::fmt::Debug;
use std::{u32, u8};

use hmac::Hmac;
use rand::{thread_rng, RngCore};
use sha2::Sha512;
use sha256::digest_bytes;

use crate::wordslist::words_list::word_list;

const MAINNET_PUBLIC_PREFIX: [u8; 4] = [4, 136, 178, 30];
const MAINNET_PRIVATE_PREFIX: [u8; 4] = [4, 136, 173, 228];
const TESTNET_PUBLIC_PREFIX: [u8; 4] = [4, 53, 135, 207];
const TESTNET_PRIVATE_PREFIX: [u8; 4] = [4, 53, 131, 148];

pub fn generate_random_entropy(strength_len: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut bytes = vec![0u8; strength_len];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn hex_to_binary_str(hex_str: String) -> String {
    let hex_str_bytes = hex::decode(hex_str).unwrap();
    hex_str_bytes
        .iter()
        .map(|v| -> String { format!("{:08b}", v) })
        .collect::<Vec<String>>()
        .join("")
}

fn vec_to_binary_str(bytes_data: Vec<u8>) -> String {
    bytes_data
        .iter()
        .map(|v| -> String { format!("{:08b}", v) })
        .collect::<Vec<String>>()
        .join("")
}

fn split_binary_str(data: String, gap: usize) -> Vec<String> {
    let i = data.len() - 1;
    let mut s = 0;
    let mut dd: Vec<String> = Vec::new();
    loop {
        if s > i {
            break;
        }
        let ss = &data[s..(s + gap)];
        dd.push(ss.parse().unwrap());
        s = s + gap;
    }
    return dd;
}

/// convert seed to mnemonic
pub fn entropy_to_mnemonic(entropy_bytes: Vec<u8>) -> String {
    let entropy_hash_str = digest_bytes(entropy_bytes.as_ref());
    let mut entropy_binary = vec_to_binary_str(entropy_bytes);
    let check_sum_len: usize = entropy_binary.len() / 32;
    let check_sum_binary_str = hex_to_binary_str(entropy_hash_str);
    let checksum = &check_sum_binary_str[0..check_sum_len];
    entropy_binary += checksum;
    let words = split_binary_str(entropy_binary, 11)
        .iter()
        .map(|v| -> u32 { string_u32(v) })
        .collect::<Vec<u32>>();
    let words_str = words
        .iter()
        .map(|index| -> String { mnemonic_at(index) })
        .collect::<Vec<String>>()
        .join(" ");
    words_str
}

/// convert mnemonic to seed
pub fn mnemonic_to_entropy(mnemonic: String) -> Vec<u8> {
    let mnemonic_words = mnemonic.split_whitespace().collect::<Vec<&str>>();
    let mut index_binary_string = mnemonic_words
        .iter()
        .map(|word| -> String { format!("{:011b}", mnemonic_index_at(word)) })
        .collect::<Vec<String>>()
        .join("");
    let check_sum_len: usize = mnemonic_words.len() / 3;
    let index_binary_seq = &index_binary_string[0..(index_binary_string.len() - check_sum_len)];
    let checksum =
        &index_binary_string[index_binary_string.len() - check_sum_len..index_binary_string.len()];
    let entropy = split_binary_str(index_binary_seq.to_string(), 8)
        .to_vec()
        .iter()
        .map(|e| -> u8 { string_u8(e) })
        .collect::<Vec<u8>>();
    let entropy_check_sum = &hex_to_binary_str(digest_bytes(entropy.as_ref()))[0..check_sum_len];
    assert_eq!(entropy_check_sum, checksum);
    entropy
}

fn string_u32(data_binary: &String) -> u32 {
    let mut mm = data_binary.len();
    let mut sum = 0;
    for i in data_binary.chars() {
        let m = i.to_digit(10).unwrap();
        let s = u32::pow(2, (mm - 1) as u32);
        sum = sum + m * s;
        mm -= 1;
    }
    return sum;
}

pub fn mnemonic_to_seed(mnemonic: String, password: String) -> [u8; 64] {
    let salt = format!("mnemonic{}", password);
    let mut res64 = [0u8; 64];
    pbkdf2::pbkdf2::<Hmac<Sha512>>(mnemonic.as_ref(), salt.as_bytes(), 2048, &mut res64);
    res64
}

/// convert seed to extended private key
pub fn seed_to_master_extend_key(seed_bytes: Vec<u8>) -> String {
    assert_eq!(seed_bytes.len(), 64);
    let left_seed = &seed_bytes[0..32];
    let right_seed = &seed_bytes[32..64];
    assert_ne!(left_seed, vec![0u8, 32]);
    let mut buffer = vec![];
    // 4 bytes: version bytes
    buffer.extend_from_slice(MAINNET_PRIVATE_PREFIX.as_slice());
    // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
    buffer.extend_from_slice([0].as_slice());
    // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
    buffer.extend_from_slice([0, 0, 0, 0].as_slice());
    // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
    // This is encoded in big endian. (0x00000000 if master key)
    buffer.extend_from_slice([0, 0, 0, 0].as_slice());
    // 32 bytes: the chain code
    buffer.extend_from_slice(right_seed);
    // 0x+privateKey
    buffer.extend_from_slice([0].as_slice());
    buffer.extend_from_slice(left_seed);
    bs58::encode(&buffer).with_check().into_string()
}

fn string_u8(data_binary: &String) -> u8 {
    let mut mm = data_binary.len();
    let mut sum: u8 = 0;
    for i in data_binary.chars() {
        let m = i.to_digit(10).unwrap() as u8;
        let s = u8::pow(2, (mm - 1) as u32);
        sum = sum + m * s;
        mm -= 1;
    }
    return sum;
}

///根据索引获取助记词单词
fn mnemonic_at(index: &u32) -> String {
    word_list()[*index as usize].to_string()
}

///根据助记词单词获取索引
fn mnemonic_index_at(word: &str) -> u32 {
    let idx = word_list().binary_search(&word.to_string()).unwrap();
    idx as u32
}

#[cfg(test)]
mod tests {
    use std::ops::Index;

    use crate::bip39::bip39::{
        entropy_to_mnemonic, generate_random_entropy, mnemonic_to_entropy, mnemonic_to_seed,
        seed_to_master_extend_key,
    };
    use crate::utils::hash512::hmac_sha512;

    #[test]
    fn it_entropy_to_mnemonic() {
        let s = std::fs::read_to_string("test_assets/vectors.json").unwrap();
        let vector: serde_json::Value = serde_json::from_str(s.as_str()).unwrap();
        let english = vector["english"].as_array().unwrap();
        for item in english {
            let seed = item.index(0).as_str().unwrap().to_string();
            let mm = item.index(1).as_str().unwrap().to_string();
            assert_eq!(entropy_to_mnemonic(hex::decode(seed).unwrap()), mm);

            let mk = mnemonic_to_seed(mm, "TREZOR".to_string());
            let mk_test = item.index(2).as_str().unwrap().to_string();
            assert_eq!(hex::encode(mk), mk_test);

            let mk_hash = hmac_sha512(hex::encode(mk).as_str());
            let mk_extend_key = seed_to_master_extend_key(mk_hash.to_vec());
            let mk_extend_key_str = item.index(3).as_str().unwrap().to_string();
            assert_eq!(mk_extend_key, mk_extend_key_str);
        }
    }

    fn test_m_entropy(len: usize) {
        let seed = generate_random_entropy(len / 8);
        let mnemonic1 = entropy_to_mnemonic(seed.clone());
        let seed2 = mnemonic_to_entropy(mnemonic1.clone());
        assert_eq!(seed, seed2);
    }

    #[test]
    fn it_m_to_entropy() {
        test_m_entropy(128);
        test_m_entropy(160);
        test_m_entropy(192);
        test_m_entropy(224);
        test_m_entropy(256);
    }

    #[test]
    fn it_test_m_to_seed() {
        let mnemonic1 = "alien tomorrow toast twice easy shine shop wagon rival rose decorate oval twelve use chief".to_string();
        let mk = mnemonic_to_seed(mnemonic1, "".to_string());
        let seed_hash = hmac_sha512(hex::encode(mk).as_str());
        assert_eq!(hex::encode(mk), "fff6d5c8cfc09e04092001a2c3a3767f4f2e860c182846ea7f81efeaee3b78251083d1db3ce49c59d21d85a3c02b0ef5086a39b32cc1fe43b17be3f4648d09e8");
    }
}
