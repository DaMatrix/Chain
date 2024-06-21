pub use ring;
use tracing::warn;
use crate::utils::serialize_utils::FixedByteArray;

macro_rules! fixed_bytes_wrapper {
    ($vis:vis struct $name:ident, $n:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
        $vis struct $name(crate::utils::serialize_utils::FixedByteArray<$n>);

        impl $name {
            pub fn from_slice(slice: &[u8]) -> Option<Self> {
                Some(Self(slice.try_into().ok()?))
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = <crate::utils::serialize_utils::FixedByteArray<$n> as std::str::FromStr>::Err;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                <crate::utils::serialize_utils::FixedByteArray<$n> as std::str::FromStr>::from_str(s).map(Self)
            }
        }
    };
}

pub mod sign_ed25519 {
    pub use ring::signature::Ed25519KeyPair as SecretKeyBase;
    use ring::signature::KeyPair;
    pub use ring::signature::Signature as SignatureBase;
    pub use ring::signature::UnparsedPublicKey;
    pub use ring::signature::{ED25519, ED25519_PUBLIC_KEY_LEN};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;
    use tracing::warn;

    pub type PublicKeyBase = <SecretKey as KeyPair>::PublicKey;

    // Constants copied from the ring library
    const SCALAR_LEN: usize = 32;
    const ELEM_LEN: usize = 32;
    const SIGNATURE_LEN: usize = ELEM_LEN + SCALAR_LEN;
    pub const ED25519_SIGNATURE_LEN: usize = SIGNATURE_LEN;

    fixed_bytes_wrapper!(pub struct Signature, ED25519_SIGNATURE_LEN, "Signature data");
    fixed_bytes_wrapper!(pub struct PublicKey, ED25519_PUBLIC_KEY_LEN, "Public key data");

    /// PKCS8 encoded secret key pair
    #[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SecretKey(#[serde(with = "crate::utils::serialize_utils::vec_codec")] Vec<u8>);

    impl SecretKey {
        /// Constructs a secret key from the given byte slice.
        ///
        /// Fails if the given slice does not contain a valid PKCS8-encoded Ed25519 secret key.
        ///
        /// ### Arguments
        ///
        /// * `slice` - a slice containing the PKCS8-encoded secret key
        pub fn from_slice(slice: &[u8]) -> Result<Self, ring::error::KeyRejected> {
            SecretKeyBase::from_pkcs8(slice)?;
            Ok(Self(slice.to_vec()))
        }

        /// Constructs a secret key from the given byte slice.
        ///
        /// This does not check if the provided data is a valid PKCS8-encoded Ed25519 secret key.
        ///
        /// ### Arguments
        ///
        /// * `slice` - a slice containing the PKCS8-encoded secret key
        pub unsafe fn from_slice_unsafe(slice: &[u8]) -> Self {
            Self(slice.to_vec())
        }

        /// Computes the public key corresponding to this private key.
        pub fn get_public_key(&self) -> PublicKey {
            let keypair = SecretKeyBase::from_pkcs8(&self.0)
                .expect("SecretKey contains invalid PKCS8 document...");
            PublicKey::from_slice(keypair.public_key().as_ref()).unwrap()
        }
    }

    impl AsRef<[u8]> for SecretKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    pub fn verify_detached(sig: &Signature, msg: &[u8], pk: &PublicKey) -> bool {
        let upk = UnparsedPublicKey::new(&ED25519, pk);
        upk.verify(msg, sig.as_ref()).is_ok()
    }

    pub fn sign_detached(msg: &[u8], sk: &SecretKey) -> Signature {
        let secret = match SecretKeyBase::from_pkcs8(sk.as_ref()) {
            Ok(secret) => secret,
            Err(_) => {
                warn!("Invalid secret key");
                return Signature([0; ED25519_SIGNATURE_LEN].into());
            }
        };

        let signature = match secret.sign(msg).as_ref().try_into() {
            Ok(signature) => signature,
            Err(_) => {
                warn!("Invalid signature");
                return Signature([0; ED25519_SIGNATURE_LEN].into());
            }
        };
        Signature(signature)
    }

    pub fn verify_append(sm: &[u8], pk: &PublicKey) -> bool {
        if sm.len() > ED25519_SIGNATURE_LEN {
            let start = sm.len() - ED25519_SIGNATURE_LEN;
            let sig = Signature(match sm[start..].try_into() {
                Ok(sig) => sig,
                Err(_) => {
                    warn!("Invalid signature");
                    return false;
                }
            });
            let msg = &sm[..start];
            verify_detached(&sig, msg, pk)
        } else {
            false
        }
    }

    pub fn sign_append(msg: &[u8], sk: &SecretKey) -> Vec<u8> {
        let sig = sign_detached(msg, sk);
        let mut sm = msg.to_vec();
        sm.extend_from_slice(sig.as_ref());
        sm
    }

    make_error_type!(pub enum GenKeypairError {
        FailedPKCS8(cause: ring::error::Unspecified);
            "Failed to generate secret key base for pkcs8: {cause}",
        InvalidSecretKey(cause: ring::error::KeyRejected);
            "Invalid secret key base: {cause}",
        InvalidPublicKey;
            "Invalid public key generation",
    });

    pub fn gen_keypair() -> Result<(PublicKey, SecretKey), GenKeypairError> {
        let rand = ring::rand::SystemRandom::new();
        gen_keypair_internal(SecretKeyBase::generate_pkcs8(&rand))
    }

    #[cfg(test)]
    pub fn gen_test_keypair(n: u64) -> Result<(PublicKey, SecretKey), GenKeypairError> {
        let seed : [u8; 32] = *super::sha3_256::digest(&n.to_le_bytes());
        let rand = ring::test::rand::FixedSliceSequenceRandom {
            bytes: &[ &seed ],
            current: core::cell::UnsafeCell::new(0),
        };
        gen_keypair_internal(SecretKeyBase::generate_pkcs8(&rand))
    }

    fn gen_keypair_internal(
        pkcs8: Result<ring::pkcs8::Document, ring::error::Unspecified>,
    ) -> Result<(PublicKey, SecretKey), GenKeypairError> {
        let pkcs8 = pkcs8.map_err(GenKeypairError::FailedPKCS8)?;

        let keypair = SecretKeyBase::from_pkcs8(pkcs8.as_ref())
            .map_err(GenKeypairError::InvalidSecretKey)?;

        let public = PublicKey::from_slice(keypair.public_key().as_ref())
            .ok_or(GenKeypairError::InvalidPublicKey)?;

        // We know that the PKCS8 document is valid because we already called
        // SecretKeyBase::from_pkcs8 on it, so we can skip the second check.
        let secret = unsafe { SecretKey::from_slice_unsafe(pkcs8.as_ref()) };

        Ok((public, secret ))
    }
}

pub mod secretbox_chacha20_poly1305 {
    // Use key and nonce separately like rust-tls does
    use super::generate_random;
    pub use ring::aead::LessSafeKey as KeyBase;
    pub use ring::aead::Nonce as NonceBase;
    pub use ring::aead::NONCE_LEN;
    use ring::aead::{Aad, UnboundKey, CHACHA20_POLY1305};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;

    pub const KEY_LEN: usize = 256 / 8;

    fixed_bytes_wrapper!(pub struct Key, KEY_LEN, "Key data");
    fixed_bytes_wrapper!(pub struct Nonce, NONCE_LEN, "Nonce data");

    pub fn seal(mut plain_text: Vec<u8>, nonce: &Nonce, key: &Key) -> Option<Vec<u8>> {
        let key = get_keybase(key)?;
        let nonce = get_noncebase(nonce);
        let aad = Aad::empty();
        let cipher_text = {
            key.seal_in_place_append_tag(nonce, aad, &mut plain_text)
                .ok()?;
            plain_text
        };
        Some(cipher_text)
    }

    pub fn open(mut cipher_text: Vec<u8>, nonce: &Nonce, key: &Key) -> Option<Vec<u8>> {
        let key = get_keybase(key)?;
        let nonce = get_noncebase(nonce);
        let aad = Aad::empty();
        let plain_text = {
            let len = key.open_in_place(nonce, aad, &mut cipher_text).ok()?.len();
            cipher_text.truncate(len);
            cipher_text
        };
        Some(plain_text)
    }

    fn get_keybase(key: &Key) -> Option<KeyBase> {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key.as_ref()).ok()?;
        Some(KeyBase::new(key))
    }

    fn get_noncebase(nonce: &Nonce) -> NonceBase {
        NonceBase::assume_unique_for_key(*nonce.0)
    }

    pub fn gen_key() -> Key {
        Key(generate_random())
    }

    pub fn gen_nonce() -> Nonce {
        Nonce(generate_random())
    }
}

pub mod pbkdf2 {
    use super::generate_random;
    use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA256};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;
    use std::num::NonZeroU32;
    use tracing::warn;

    pub const SALT_LEN: usize = 256 / 8;
    pub const OPSLIMIT_INTERACTIVE: u32 = 100_000;

    fixed_bytes_wrapper!(pub struct Salt, SALT_LEN, "Salt data");

    pub fn derive_key(key: &mut [u8], passwd: &[u8], salt: &Salt, iterations: u32) {
        let iterations = match NonZeroU32::new(iterations) {
            Some(iterations) => iterations,
            None => {
                warn!("Invalid iterations in key derivation");
                return;
            }
        };
        derive(PBKDF2_HMAC_SHA256, iterations, salt.as_ref(), passwd, key);
    }

    pub fn gen_salt() -> Salt {
        Salt(generate_random())
    }
}

pub mod sha3_256 {
    use std::convert::TryInto;
    use std::fmt::{Display, Formatter};
    use std::ops::Deref;
    use std::str::FromStr;

    pub use sha3::digest::Output;
    pub use sha3::Digest;
    pub use sha3::Sha3_256;

    pub const HASH_LEN : usize = 256 / 8;

    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq)]
    pub struct Hash(
        [u8; HASH_LEN],
    );

    impl Hash {
        pub fn from_slice(slice: &[u8]) -> Option<Self> {
            Some(Self(slice.try_into().ok()?))
        }
    }

    impl Display for Hash {
        fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
            f.write_str(&hex::encode(&self.0))
        }
    }

    impl FromStr for Hash {
        type Err = hex::FromHexError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut buf = [0u8; HASH_LEN];
            match hex::decode_to_slice(s, &mut buf) {
                Ok(_) => Ok(Self(buf)),
                Err(e) => Err(e),
            }
        }
    }

    impl AsRef<[u8]> for Hash {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Deref for Hash {
        type Target = [u8; HASH_LEN];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    pub fn digest(data: &[u8]) -> Hash {
        Hash(Sha3_256::digest(data).try_into().unwrap())
    }

    pub fn digest_all<'a>(data: impl Iterator<Item = &'a [u8]>) -> Hash {
        let mut hasher = Sha3_256::new();
        data.for_each(|v| hasher.update(v));
        Hash(hasher.finalize().try_into().unwrap())
    }
}

fn generate_random<const N: usize>() -> FixedByteArray<N> {
    let mut value: [u8; N] = [0; N];

    use ring::rand::SecureRandom;
    let rand = ring::rand::SystemRandom::new();
    match rand.fill(&mut value) {
        Ok(_) => (),
        Err(_) => warn!("Failed to generate random bytes"),
    };

    FixedByteArray::new(value)
}
