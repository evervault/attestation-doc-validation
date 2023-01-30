pub(crate) use aws_nitro_enclaves_cose::crypto::Hash;
use aws_nitro_enclaves_cose::crypto::{
    Decryption, Encryption, EncryptionAlgorithm, Entropy, MessageDigest,
};
use aws_nitro_enclaves_cose::error::CoseError;
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::aead::{Algorithm, AES_128_GCM, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

struct NonceProvider<'a> {
    nonce: Option<&'a [u8]>,
}

impl<'a> std::convert::From<Option<&'a [u8]>> for NonceProvider<'a> {
    fn from(value: Option<&'a [u8]>) -> Self {
        Self { nonce: value }
    }
}

impl NonceSequence for NonceProvider<'_> {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let maybe_nonce = self.nonce.take();
        match maybe_nonce {
            Some(nonce) => Nonce::try_assume_unique_for_key(&nonce[..12]),
            None => Err(ring::error::Unspecified),
        }
    }
}

/// Type that implements various cryptographic traits
pub(crate) struct RingClient;

impl Entropy for RingClient {
    fn rand_bytes(buff: &mut [u8]) -> Result<(), CoseError> {
        // TODO: evaluate performance of creating a new sys random client
        let rng = SystemRandom::new();
        let _ = rng.fill(buff);
        Ok(())
    }
}

fn get_ring_cipher_from_encryption_algorithm(algorithm: EncryptionAlgorithm) -> &'static Algorithm {
    match algorithm {
        EncryptionAlgorithm::Aes128Gcm => &AES_128_GCM,
        EncryptionAlgorithm::Aes192Gcm => unimplemented!(),
        EncryptionAlgorithm::Aes256Gcm => &AES_256_GCM,
    }
}

impl Encryption for RingClient {
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
        let cipher = get_ring_cipher_from_encryption_algorithm(algo);

        let unbound_aes_key = UnboundKey::new(&cipher, key).unwrap();
        let mut aes_key = SealingKey::new(unbound_aes_key, NonceProvider::from(iv));
        let aad = Aad::from(aad);

        let mut ciphertext = data.to_vec();
        let generated_tag = aes_key
            .seal_in_place_separate_tag(aad, &mut ciphertext)
            .unwrap();

        let tag_bytes = generated_tag.as_ref();
        tag.copy_from_slice(&tag_bytes[..tag_bytes.len()]);
        Ok(ciphertext)
    }
}

impl Decryption for RingClient {
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
        let cipher = get_ring_cipher_from_encryption_algorithm(algo);

        let unbound_aes_key = UnboundKey::new(&cipher, key).unwrap();
        let mut aes_key = OpeningKey::new(unbound_aes_key, NonceProvider::from(iv));

        let aad = Aad::from(aad);
        let mut tagged_ciphertext = vec![ciphertext, tag].concat();
        let plaintext = aes_key.open_in_place(aad, &mut tagged_ciphertext).unwrap();

        Ok(plaintext.to_vec())
    }
}

fn get_ring_algorithm_from_message_digest<'a>(
    digest: MessageDigest,
) -> &'a ring::digest::Algorithm {
    match digest {
        MessageDigest::Sha256 => &ring::digest::SHA256,
        MessageDigest::Sha384 => &ring::digest::SHA384,
        MessageDigest::Sha512 => &ring::digest::SHA512,
    }
}

impl Hash for RingClient {
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        let algorithm = get_ring_algorithm_from_message_digest(digest);
        let hashed_input = ring::digest::digest(algorithm, data);
        Ok(hashed_input.as_ref().to_vec())
    }
}

#[cfg(test)]
mod test {
    use super::{Hash, MessageDigest, RingClient};
    #[test]
    fn test_ring_client_hashing() {
        let result = RingClient::hash(MessageDigest::Sha384, b"test");
        let hash = result.unwrap();
        assert_eq!("768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9".to_string(), hex::encode(&hash));
    }
}
