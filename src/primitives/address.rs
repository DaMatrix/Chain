use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::crypto::sha3_256;
use crate::utils::Placeholder;
use crate::utils::serialize_utils::FixedByteArray;

pub const STANDARD_ADDRESS_BYTES : usize = sha3_256::HASH_LEN;

/// A standard 32-byte address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StandardAddress(FixedByteArray<STANDARD_ADDRESS_BYTES>);

impl StandardAddress {
    pub const BYTES : usize = sha3_256::HASH_LEN;

    /// Creates a new address out of the given SHA3-256 `Hash`.
    fn new(hash: sha3_256::Hash) -> Self {
        Self(hash.deref().into())
    }
}

impl Placeholder for StandardAddress {
    fn placeholder_indexed(index: u64) -> Self {
        Self::new(sha3_256::digest(&index.to_le_bytes()))
    }
}

impl Display for StandardAddress {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(&hex::encode(self.as_ref()))
    }
}

impl FromStr for StandardAddress {
    type Err = <FixedByteArray<STANDARD_ADDRESS_BYTES> as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        sha3_256::Hash::from_str(s).map(Self::new)
    }
}

impl AsRef<[u8]> for StandardAddress {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

make_error_type!(pub enum ParseAddressError {
    BadPrefix(address: String); "Address \"{address}\" has unknown prefix",
    ParseFailed(cause: <StandardAddress as FromStr>::Err); "{cause}"; cause,
});

macro_rules! standard_address_type {
    ($doc:literal, $name:ident, $prefix:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(StandardAddress);

        impl $name {
            /// Creates a new address out of the given SHA3-256 `Hash`.
            pub fn new(hash: sha3_256::Hash) -> Self {
                Self(StandardAddress::new(hash))
            }
        }

        impl Placeholder for $name {
            fn placeholder() -> Self {
                Self(StandardAddress::placeholder())
            }

            fn placeholder_indexed(index: u64) -> Self {
                Self(StandardAddress::placeholder_indexed(index))
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }

        impl FromStr for $name {
            type Err = ParseAddressError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if let Some(s) = s.strip_prefix($prefix) {
                    StandardAddress::from_str(s).map(Self).map_err(ParseAddressError::ParseFailed)
                } else {
                    Err(ParseAddressError::BadPrefix(s.to_string()))
                }
            }
        }
    };
}

standard_address_type!("The type of address used for P2PKH outputs", P2PKHAddress, "");

standard_address_type!("The type of address used for P2SH outputs", P2SHAddress, "H");

/// Wrapper enum representing an address of any type.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum AnyAddress {
    P2PKH(P2PKHAddress),
    P2SH(P2SHAddress),
}

impl Display for AnyAddress {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            AnyAddress::P2PKH(address) => address.fmt(f),
            AnyAddress::P2SH(address) => address.fmt(f),
        }
    }
}

impl FromStr for AnyAddress {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = P2PKHAddress::from_str(s) {
            Ok(Self::P2PKH(addr))
        } else if let Ok(addr) = P2SHAddress::from_str(s) {
            Ok(Self::P2SH(addr))
        } else {
            Err(ParseAddressError::BadPrefix(s.to_string()))
        }
    }
}
