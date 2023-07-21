use ecdsa::hazmat::SignPrimitive;
use std::borrow::Borrow;
use std::ops::Mul;

use k256::elliptic_curve::{AffineXCoordinate, PrimeField, ScalarCore, SecretKey};
use k256::{NonZeroScalar, Scalar};

use k256::ecdsa::signature::SignerMut;
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};

use crate::utils::convert_math::{bytes_to_u32, bytes_to_u8};
use crate::utils::hash512::{hash160, hash_keccake256, hmac_sha512, hmac_sha512_p2};

const HIGHEST_BIT: u32 = 0x80000000;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtendedKeypair {
    extend_private_key: String,
    extend_public_key: String,
}

impl PartialEq for ExtendedKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.extend_private_key == other.extend_private_key
            && self.extend_public_key == other.extend_public_key
    }
}

impl ExtendedKeypair {
    pub fn new(extend_private_key: String, extend_public_key: String) -> ExtendedKeypair {
        ExtendedKeypair {
            extend_private_key,
            extend_public_key,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Bip32ExtendedKeyPairPrefix {
    public_prefix: Vec<u8>,
    private_prefix: Vec<u8>,
}

impl Bip32ExtendedKeyPairPrefix {
    pub fn new(public_prefix: Vec<u8>, private_prefix: Vec<u8>) -> Bip32ExtendedKeyPairPrefix {
        Bip32ExtendedKeyPairPrefix {
            public_prefix,
            private_prefix,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Bip32Network {
    message_prefix: String,
    bech32: String,
    pub_key_hash: Vec<u8>,
    script_hash: Vec<u8>,
    wif: Vec<u8>,
    bi32: Bip32ExtendedKeyPairPrefix,
}

impl Bip32Network {
    pub fn new(
        message_prefix: String,
        bech32: String,
        pub_key_hash: Vec<u8>,
        script_hash: Vec<u8>,
        wif: Vec<u8>,
        bi32: Bip32ExtendedKeyPairPrefix,
    ) -> Bip32Network {
        Bip32Network {
            message_prefix,
            bech32,
            pub_key_hash,
            script_hash,
            wif,
            bi32,
        }
    }
    pub fn default() -> Bip32Network {
        Bip32Network {
            message_prefix: "\x18Bitcoin Signed Message:\n".to_string(),
            bech32: "bc".to_string(),
            pub_key_hash: [0].to_vec(),
            script_hash: hex::decode("05").expect("invalid hex str"),
            wif: hex::decode("80").expect("invalid hex str"),
            bi32: Bip32ExtendedKeyPairPrefix::new(
                hex::decode("0488b21e").unwrap(),
                hex::decode("0488ade4").unwrap(),
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Bip32 {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    network: Bip32Network,
    chain_code: Vec<u8>,
    depth: u8,
    index: u32,
    parent_fingerprint: u32,
}

impl Bip32 {
    pub fn from_seed(seed: Vec<u8>, network: Option<Bip32Network>) -> Bip32 {
        let seed_hash = hmac_sha512(hex::encode(seed).as_str());
        assert_eq!(seed_hash.len(), 64);
        let left_seed = seed_hash[0..32].to_vec();
        let right_seed = seed_hash[32..64].to_vec();
        assert_ne!(left_seed, vec![0u8, 32]);
        match network {
            Some(network) => Bip32::from_private_key(left_seed, right_seed, network),
            None => Bip32::from_private_key(left_seed, right_seed, Bip32Network::default()),
        }
    }

    pub fn from_base58(base58_str: String, network: Option<Bip32Network>) -> Bip32 {
        let network = match network {
            Some(net) => net,
            None => Bip32Network::default(),
        };

        let bs58_bytes = bs58::decode(base58_str)
            .with_check(None)
            .into_vec()
            .unwrap();
        assert_eq!(bs58_bytes.len(), 78);
        // 4 bytes: version bytes
        let version_bytes = &bs58_bytes[0..4];
        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
        let depth_bytes = &bs58_bytes[4..5];
        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        let fingerprint_bytes = &bs58_bytes[5..9];
        // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
        let index_bytes = &bs58_bytes[9..13].to_vec();
        // 32 bytes: the chain code
        let chain_code_bytes = &bs58_bytes[13..45];
        let key_bytes = &bs58_bytes[45..78].to_vec();
        if version_bytes.to_vec() == network.bi32.public_prefix {
            Bip32::from_public_key_local(
                key_bytes.to_vec(),
                chain_code_bytes.to_vec(),
                network,
                bytes_to_u32(index_bytes),
                bytes_to_u8(depth_bytes),
                bytes_to_u32(fingerprint_bytes),
            )
        } else {
            Bip32::from_private_key_local(
                key_bytes[1..33].to_vec(),
                chain_code_bytes.to_vec(),
                network,
                0,
                0,
                0,
            )
        }
    }
    pub fn from_public_key(
        public_key: Vec<u8>,
        chain_code: Vec<u8>,
        network: Bip32Network,
    ) -> Bip32 {
        Bip32 {
            private_key: vec![],
            public_key,
            network,
            chain_code,
            depth: 0,
            index: 0,
            parent_fingerprint: 0,
        }
    }

    pub fn from_private_key(
        private_key: Vec<u8>,
        chain_code: Vec<u8>,
        network: Bip32Network,
    ) -> Bip32 {
        let secp = k256::SecretKey::from_be_bytes(private_key.as_ref()).unwrap();
        let pubkey = secp.public_key().to_encoded_point(true).as_bytes().to_vec();

        Bip32 {
            private_key,
            public_key: pubkey,
            network,
            chain_code,
            depth: 0,
            index: 0,
            parent_fingerprint: 0,
        }
    }
}

impl Bip32 {
    pub fn from_public_key_local(
        public_key: Vec<u8>,
        chain_code: Vec<u8>,
        network: Bip32Network,
        index: u32,
        depth: u8,
        parent_fingerprint: u32,
    ) -> Bip32 {
        Bip32 {
            private_key: vec![],
            public_key,
            network,
            chain_code,
            depth,
            index,
            parent_fingerprint,
        }
    }
    pub fn from_private_key_local(
        private_key: Vec<u8>,
        chain_code: Vec<u8>,
        network: Bip32Network,
        index: u32,
        depth: u8,
        parent_fingerprint: u32,
    ) -> Bip32 {
        let secp = k256::SecretKey::from_be_bytes(private_key.as_ref()).unwrap();
        let pubkey = secp.public_key().to_encoded_point(true).as_bytes().to_vec();
        Bip32 {
            private_key,
            public_key: pubkey,
            network,
            chain_code,
            depth,
            index,
            parent_fingerprint,
        }
    }

    pub fn sign(&self, data: Vec<u8>) -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(self.private_key.as_ref()).unwrap();
        let vv = hash_keccake256(data);
        let (signature, recid) = signing_key.sign_prehash_recoverable(&vv).unwrap();
        let mut buffer = vec![];
        buffer.extend_from_slice(&signature.to_vec());
        buffer.extend_from_slice(&*vec![recid.to_byte()]);
        buffer
    }
    pub fn sign_prehash(&self, data: Vec<u8>) -> Vec<u8> {
        let signing_key = SigningKey::from_bytes(self.private_key.as_ref()).unwrap();
        let (signature, recid) = signing_key.sign_prehash_recoverable(&data).unwrap();
        let mut buffer = vec![];
        buffer.extend_from_slice(&signature.to_vec());
        buffer.extend_from_slice(&*vec![recid.to_byte()]);
        buffer
    }
    pub fn neutered(&self) -> bool {
        return !self.private_key.is_empty();
    }
    fn to_pri_base58(&self) -> String {
        if !self.neutered() {
            return "".to_string();
        }
        let mut buffer: Vec<u8> = vec![];
        // 4 bytes: version bytes
        buffer.extend_from_slice(&self.network.bi32.private_prefix.as_slice());
        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....

        buffer.extend_from_slice(&self.depth.to_be_bytes());
        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        buffer.extend_from_slice(&self.parent_fingerprint.to_be_bytes());
        // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
        // This is encoded in big endian. (0x00000000 if master key)
        buffer.extend_from_slice(&self.index.to_be_bytes());
        // 32 bytes: the chain code
        buffer.extend_from_slice(self.chain_code.as_slice());
        buffer.extend_from_slice([0].as_slice());
        buffer.extend_from_slice(&self.private_key.clone().as_slice());
        bs58::encode(&buffer).with_check().into_string()
    }

    fn to_pubkey_base58(&self) -> String {
        let mut buffer: Vec<u8> = vec![];

        // 4 bytes: version bytes
        buffer.extend_from_slice(self.network.bi32.public_prefix.as_slice());
        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
        buffer.extend_from_slice(&self.depth.to_be_bytes());
        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        buffer.extend_from_slice(&self.parent_fingerprint.to_be_bytes());
        // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
        // This is encoded in big endian. (0x00000000 if master key)
        buffer.extend_from_slice(&self.index.to_be_bytes());
        // 32 bytes: the chain code
        buffer.extend_from_slice(self.chain_code.as_slice());
        buffer.extend_from_slice(&self.public_key.clone());
        bs58::encode(&buffer).with_check().into_string()
    }
    pub fn to_base58(&self) -> ExtendedKeypair {
        ExtendedKeypair::new(self.to_pri_base58(), self.to_pubkey_base58())
    }
    pub fn to_wif(&self) {}

    pub fn derive(&mut self, index: u32) -> Bip32 {
        self.index = index;
        let mut data: Vec<u8> = vec![];
        if index >= HIGHEST_BIT {
            data.extend_from_slice([0].as_slice());
            data.extend_from_slice(&self.private_key.clone().as_slice());
            data.extend_from_slice(&index.to_be_bytes());
        } else {
            data.extend_from_slice(&self.public_key.clone().as_slice());
            data.extend_from_slice(&index.to_be_bytes());
        }

        let I = hmac_sha512_p2(self.chain_code.to_vec(), data.to_vec());
        let IL = &I[0..32];
        let IR = &I[32..64];
        if self.neutered() {
            let old_private_key: NonZeroScalar =
                SecretKey::from_be_bytes(&self.private_key.as_slice())
                    .unwrap()
                    .to_nonzero_scalar();

            let new_private_key: NonZeroScalar =
                SecretKey::from_be_bytes(IL).unwrap().to_nonzero_scalar();
            // throw if IL >= n || (privateKey + IL) === 0
            let s = old_private_key.as_ref() + new_private_key.as_ref();
            Bip32::from_private_key_local(
                s.to_bytes().to_vec(),
                IR.to_vec(),
                self.network.clone(),
                self.index,
                self.depth + 1,
                self.fingerprint(),
            )
        } else {
            // G*IL + Kpar
            let old_private_key =
                k256::PublicKey::from_sec1_bytes(self.public_key.as_slice()).unwrap();
            let s = Scalar::from(ScalarCore::from_be_slice(IL).unwrap());
            let g = k256::ProjectivePoint::GENERATOR * &s;
            let k = g.mul(s) + old_private_key.to_projective();
            let dd = k256::PublicKey::try_from(k).unwrap();
            let pk = dd.to_encoded_point(true).as_bytes().to_vec();
            Bip32::from_public_key_local(
                pk,
                IR.to_vec(),
                self.network.clone(),
                self.index,
                self.depth + 1,
                self.fingerprint(),
            )
        }
    }

    pub fn fingerprint_all(&self) -> Vec<u8> {
        hash160(self.public_key.to_vec())
    }

    pub fn fingerprint(&self) -> u32 {
        let ff = hash160(self.public_key.to_vec());
        let mut buffer = [0u8; 4];
        buffer.clone_from_slice(ff[0..4].as_ref());
        u32::from_be_bytes(buffer)
    }
    pub fn derive_hardened(&mut self, index: u32) -> Bip32 {
        self.derive(HIGHEST_BIT + index)
    }
    pub fn derive_path(self, path: String) -> Bip32 {
        let mut idx = path
            .split("/")
            .map(|v| -> String { v.to_string() })
            .collect::<Vec<String>>();
        let start: &[_] = &['m', 'M'];
        assert_ne!(idx[0].rfind(start), None);
        idx.remove(0);
        let mut bip32 = self.clone();
        idx.iter().fold(bip32, move |mut cur, next| -> Bip32 {
            if next.contains("'") {
                let index_vec = next.split("'").map(|v| v).collect::<Vec<&str>>();
                let index_num = index_vec[0].parse::<u32>().unwrap();
                cur.derive_hardened(index_num)
            } else {
                let index = next.parse::<u32>().unwrap();
                cur.derive(index)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;
    use std::ops::Index;

    use crate::bip32::bip32::Bip32;
    use crate::bip39::bip39::{entropy_to_mnemonic, mnemonic_to_seed};

    use crate::utils::hash512::{hash_keccake256, hmac_sha512};

    #[test]
    fn it_test_to_base58() {
        let s = std::fs::read_to_string("test_assets/vectors.json").unwrap();
        let vector: serde_json::Value = serde_json::from_str(s.as_str()).unwrap();
        let english = vector["english"].as_array().unwrap();
        for item in english {
            let mm = item.index(1).as_str().unwrap().to_string();
            let mk = mnemonic_to_seed(mm, "TREZOR".to_string());
            let mk_extend_key = Bip32::from_seed(mk.to_vec(), None).to_base58();
            let mk_extend_key_str = item.index(3).as_str().unwrap().to_string();
            assert_eq!(mk_extend_key, mk_extend_key);
        }
    }

    #[test]
    fn it_test() {
        let mut bip = Bip32::from_seed(
            hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
            None,
        );
        let bip_1 = bip.derive(0).derive(0).derive(0);
        println!("{:?}", bip_1.to_base58());
    }

    #[test]
    fn it_test_harded() {
        let mut bip = Bip32::from_seed(
            hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(),
            None,
        );
        // assert_eq!(bip.derive_path("m/1'/1'/3".to_string()).to_base58().extend_private_key, "xprv9y2oBTEMpwzW7xNf2CfZwJ24GbpDmpk7cVGa9CZdnJ1YWNfnahtWkH1fzgQfhHPmhJMRprUAbf17LDLQ4yJ84hB4E8S5JU2P1gdCSk3sYbq");
        let ss = &bip.sign("Hello".as_bytes().to_vec());
    }

    #[test]
    fn it_test_generate_pubkey() {
        let private_key_byte =
            hex::decode("1f2b77e3a4b50120692912c94b204540ad44404386b10c615786a7efaa065d20")
                .unwrap();
        let private_key = SecretKey::from_be_bytes(private_key_byte.as_ref()).unwrap();
        let mut pubkey = private_key
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let oubkey_hex = hex::encode(&pubkey);
        println!(" pubkey:={:?}", hex::encode(&pubkey));
        let hh = hash_keccake256(pubkey.split_at(1).1.to_vec());
        println!("{:?}", hex::encode(hh));
    }
}
