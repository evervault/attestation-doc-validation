pub(crate) use aws_nitro_enclaves_cose::crypto::Hash;
use aws_nitro_enclaves_cose::crypto::{
    Decryption, Encryption, EncryptionAlgorithm, Entropy, MessageDigest,
};
use aws_nitro_enclaves_cose::error::CoseError;

use aes::cipher::consts::U12;
use aes::Aes192;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, AesGcm, Nonce as AesNonce,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha384, Sha512};

type Aes192Gcm = AesGcm<Aes192, U12>;

/// Type that implements various cryptographic traits
pub(crate) struct CryptoClient;

impl Entropy for CryptoClient {
    fn rand_bytes(buff: &mut [u8]) -> Result<(), CoseError> {
        OsRng.fill_bytes(buff);
        Ok(())
    }
}

macro_rules! aes_encryption {
    ($func_name:ident, $cipher:ident) => {
        fn $func_name(
            key: &[u8],
            iv: Option<&[u8]>,
            aad: &[u8],
            data: &[u8],
            tag: &mut [u8],
        ) -> Result<Vec<u8>, CoseError> {
            let cipher = $cipher::new_from_slice(key).unwrap();
            let nonce = AesNonce::from_slice(iv.unwrap());
            let authenticated_payload = Payload { msg: data, aad };
            let encrypted = cipher.encrypt(nonce, authenticated_payload).unwrap();
            let (ciphertext, computed_tag) = encrypted.split_at(encrypted.len() - 16);
            tag.copy_from_slice(&computed_tag[..]);
            return Ok(ciphertext.to_vec());
        }
    };
}

macro_rules! aes_decryption {
    ($func_name:ident, $cipher:ident) => {
        fn $func_name(
            key: &[u8],
            iv: Option<&[u8]>,
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8],
        ) -> Result<Vec<u8>, CoseError> {
            let cipher = $cipher::new_from_slice(key).unwrap();
            let nonce = AesNonce::from_slice(iv.unwrap());
            let tagged_cipher = [ciphertext, tag].concat();
            let authenticated_payload = Payload {
                msg: tagged_cipher.as_ref(),
                aad,
            };
            let decrypted = cipher.decrypt(nonce, authenticated_payload).unwrap();
            return Ok(decrypted);
        }
    };
}

aes_encryption!(perform_aes_128_gcm_encryption, Aes128Gcm);
aes_decryption!(perform_aes_128_gcm_decryption, Aes128Gcm);

aes_encryption!(perform_aes_192_gcm_encryption, Aes192Gcm);
aes_decryption!(perform_aes_192_gcm_decryption, Aes192Gcm);

aes_encryption!(perform_aes_256_gcm_encryption, Aes256Gcm);
aes_decryption!(perform_aes_256_gcm_decryption, Aes256Gcm);

impl Encryption for CryptoClient {
    /// Like `encrypt`, but for AEAD ciphers such as AES GCM.
    ///
    /// Additional Authenticated Data can be provided in the `aad` field, and the authentication tag
    /// will be copied into the `tag` field.
    ///
    /// The size of the `tag` buffer indicates the required size of the tag. While some ciphers support
    /// a range of tag sizes, it is recommended to pick the maximum size. For AES GCM, this is 16 bytes,
    /// for example.
    fn encrypt_aead(
        algo: EncryptionAlgorithm,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: &[u8],
        data: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>, CoseError> {
        let encryption_func = match algo {
            EncryptionAlgorithm::Aes128Gcm => perform_aes_128_gcm_encryption,
            EncryptionAlgorithm::Aes192Gcm => perform_aes_192_gcm_encryption,
            EncryptionAlgorithm::Aes256Gcm => perform_aes_256_gcm_encryption,
        };
        encryption_func(key, iv, aad, data, tag)
    }
}

impl Decryption for CryptoClient {
    /// Like `decrypt`, but for AEAD ciphers such as AES GCM.
    ///
    /// Additional Authenticated Data can be provided in the `aad` field, and the authentication tag
    /// should be provided in the `tag` field.
    fn decrypt_aead(
        algo: EncryptionAlgorithm,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, CoseError> {
        let decryption_func = match algo {
            EncryptionAlgorithm::Aes128Gcm => perform_aes_128_gcm_decryption,
            EncryptionAlgorithm::Aes192Gcm => perform_aes_192_gcm_decryption,
            EncryptionAlgorithm::Aes256Gcm => perform_aes_256_gcm_decryption,
        };
        decryption_func(key, iv, aad, ciphertext, tag)
    }
}

macro_rules! compute_hash {
    ($hash:ident, $data:ident) => {
        let mut hasher = $hash::new();
        hasher.update($data);
        let msg_digest = hasher.finalize();
        return Ok(msg_digest.to_vec());
    };
}

impl Hash for CryptoClient {
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        match digest {
            MessageDigest::Sha256 => {
                compute_hash!(Sha256, data);
            }
            MessageDigest::Sha384 => {
                compute_hash!(Sha384, data);
            }
            MessageDigest::Sha512 => {
                compute_hash!(Sha512, data);
            }
        }
    }
}
