use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};

type Ctr = ctr::Ctr128BE<Aes256>;

pub struct AesCtr(Ctr);

impl AesCtr {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        assert_eq!(key.len(), 32, "AES-256 key must be 32 bytes");
        assert_eq!(iv.len(), 16, "CTR IV must be 16 bytes");
        Self(Ctr::new(key.into(), iv.into()))
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        self.0.apply_keystream(data);
    }

    pub fn update(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        self.0.apply_keystream(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_sp800_38a_aes256_ctr_vector() {
        let key = hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .unwrap();
        let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let plain = hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
        )
        .unwrap();
        let expected = hex::decode(
            "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5",
        )
        .unwrap();
        let mut cipher = AesCtr::new(&key, &iv);
        assert_eq!(cipher.update(&plain), expected);
    }

    #[test]
    fn stream_state_continues_across_calls() {
        let key = [7u8; 32];
        let iv = [9u8; 16];
        let data: Vec<u8> = (0..200u32).map(|v| v as u8).collect();
        let mut whole = AesCtr::new(&key, &iv);
        let expected = whole.update(&data);
        let mut parts = AesCtr::new(&key, &iv);
        let mut joined = parts.update(&data[..13]);
        joined.extend(parts.update(&data[13..97]));
        joined.extend(parts.update(&data[97..]));
        assert_eq!(joined, expected);
    }

    #[test]
    fn counter_wraps_across_full_128_bits_like_big_endian_ctr() {
        let key = [1u8; 32];
        let iv = [0xffu8; 16];
        let mut cipher = AesCtr::new(&key, &iv);
        let first = cipher.update(&[0u8; 32]);
        let mut again = AesCtr::new(&key, &[0u8; 16]);
        let second_block = again.update(&[0u8; 16]);
        assert_eq!(&first[16..], &second_block[..]);
    }

    #[test]
    fn decrypt_is_symmetric() {
        let key = [3u8; 32];
        let iv = [4u8; 16];
        let mut enc = AesCtr::new(&key, &iv);
        let mut dec = AesCtr::new(&key, &iv);
        let data = b"hello mtproto".to_vec();
        let cipher_text = enc.update(&data);
        assert_ne!(cipher_text, data);
        assert_eq!(dec.update(&cipher_text), data);
    }
}
