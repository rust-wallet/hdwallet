use crate::bip32::bip32::Bip32;
use crate::bip39::bip39::{entropy_to_mnemonic, generate_random_entropy, mnemonic_to_seed};
use crate::utils::convert_math::bytes_to_u32;

pub struct HDWallet {
    bip32: Bip32,
    mnemonic: String,
    seed: [u8; 64],
}

impl HDWallet {
    /// create new HDWallet
    /// [strength_len]  强度  128,160,192,224,256
    pub fn new(strength_len: usize, password: Option<String>) -> HDWallet {
        let p = match password {
            Some(v) => v,
            None => "".to_string(),
        };
        let v: [u32; 5] = [128, 160, 192, 224, 256];
        assert!(v.contains(&bytes_to_u32(strength_len.to_be_bytes().as_ref())));
        let entropy = generate_random_entropy(strength_len / 8);
        let mnemonic = entropy_to_mnemonic(entropy);
        let seed = mnemonic_to_seed(mnemonic.clone(), p);
        let bip = Bip32::from_seed(seed.to_vec(), None);
        HDWallet {
            bip32: bip,
            mnemonic: mnemonic.clone(),
            seed,
        }
    }

    pub fn new_from_mnemonic(mnemonic: String, password: Option<String>) -> HDWallet {
        let p = match password {
            Some(v) => v,
            None => "".to_string(),
        };
        let seed = mnemonic_to_seed(mnemonic.clone(), p);
        let bip = Bip32::from_seed(seed.to_vec(), None);
        HDWallet {
            bip32: bip,
            mnemonic,
            seed,
        }
    }
}

impl HDWallet {
    pub fn derive(mut self, path: String) {
        let bip = self.bip32.derive_path(path);
        println!("{:?}", serde_json::to_string(&bip.to_base58()))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::hdwallet::hdwallet::HDWallet;

    #[test]
    fn it_test_new_hd_wallet() {
        let hdwallet = HDWallet::new_from_mnemonic("wage toward quality scatter inspire prevent bronze scrap sponsor silent giraffe reveal sorry runway unlock".to_string(), None);
        hdwallet.derive("m/44'/0'/0'/0".to_string());
    }
}
