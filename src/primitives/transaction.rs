#![allow(unused)]

use std::convert::{TryFrom, TryInto};
use crate::constants::*;
use crate::crypto::sign_ed25519::{PublicKey, SecretKey, Signature};
use crate::primitives::{
    asset::{Asset, ItemAsset, TokenAmount},
    druid::{DdeValues, DruidExpectation},
};
use crate::script::lang::Script;
use crate::script::{OpCodes, ScriptEntry, StackEntry};
use crate::utils::{FromOrdinal, is_valid_amount, Placeholder, ToOrdinal};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::Formatter;
use std::str::{from_utf8, FromStr};
use bincode::{Decode, Encode, impl_borrow_decode};
use bincode::de::Decoder;
use bincode::enc::Encoder;
use bincode::enc::write::Writer;
use bincode::error::{AllowedEnumVariants, DecodeError, EncodeError};
use serde::ser::SerializeStruct;
use crate::crypto::sha3_256;
use crate::primitives::address::AnyAddress;
use crate::primitives::format::v6;

make_ordinal_enum!(
#[doc = "The supported transaction versions"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxVersion {
    #[doc = "Transaction version 6."]
    #[doc = "This is the version used when the AIBlock network first went live."]
    V6 = 6,
}
all_variants=pub ALL_VERISONS);

impl TxVersion {
    /// The most recent transaction version.
    pub const LATEST : Self = Self::V6;
}

impl Encode for TxVersion {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        <u32 as bincode::Encode>::encode(&self.to_ordinal(), encoder)
    }
}

impl Decode for TxVersion {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
        let ordinal = <u32 as bincode::Decode>::decode(decoder)?;

        Self::from_ordinal(ordinal)
            .map_err(|ordinal| DecodeError::UnexpectedVariant {
                type_name: "TxVersion",
                allowed: &AllowedEnumVariants::Allowed(Self::ALL_ORDINALS),
                found: ordinal,
            })
    }
}
impl_borrow_decode!(TxVersion);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GenesisTxHashSpec {
    Create,
    Default,
    //TODO: Eventually custom?
}

impl GenesisTxHashSpec {
    pub fn get_genesis_hash(&self) -> Option<String> {
        match self {
            GenesisTxHashSpec::Create => None, /* Unique DRS transaction hash will be assigned */
            GenesisTxHashSpec::Default => Some(ITEM_DEFAULT_DRS_TX_HASH.to_string()),
        }
    }
}

/// A user-friendly construction struct for a TxIn
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[deprecated = "This is no longer necessary"]
pub struct TxConstructor {
    pub previous_out: OutPoint,
    #[deprecated = "This is never accessed"]
    pub signatures: Vec<Signature>,
    #[deprecated = "This is never accessed"]
    pub pub_keys: Vec<PublicKey>,
}

const TX_HASH_LENGTH_BYTES : usize = TX_HASH_LENGTH / 2;

/// Compact transaction hash representation.
///
/// For legacy reasons, this wraps 31 hexadecimal digits worth of data, equivalent to 15.5 bytes.
/// Because of this, the 4 least significant bits of the last byte are unused. While awkward, this
/// actually means we have a convenient location to squeeze in a version indicator if we decide to
/// extend the transaction hash size in the future.
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Encode, Decode)]
pub struct TxHash([u8; TX_HASH_LENGTH_BYTES]);

make_error_type!(
#[derive(PartialEq)]
pub enum TxHashError {
    BadByteCount(size: usize); "Transaction hash needs {TX_HASH_LENGTH_BYTES} bytes, got {size}",
    BadZeroBits; "Transaction hash must end with four zero bits",

    InvalidStringLength(input: String); "Transaction hash \"{input}\" has incorrect length",
    InvalidPrefix(input: String); "Transaction hash \"{input}\" has incorrect prefix",
    InvalidHexData(input: String, cause: hex::FromHexError); "Transaction hash \"{input}\" is invalid: {cause}"; cause,
});

impl TxHash {
    /// Constructs a new `TransactionHash` from the given bytes.
    ///
    /// Fails if the given slice does not contain a valid encoded `TransactionHash`.
    pub fn from_slice(slice: &[u8]) -> Result<Self, TxHashError> {
        let bytes : [u8; TX_HASH_LENGTH_BYTES] = slice.try_into()
            .map_err(|_| TxHashError::BadByteCount(slice.len()))?;

        // The four least significant bits of the last byte must be zero, as a transaction
        // hash consists of an odd number of hexadecimal digits.
        if (bytes[TX_HASH_LENGTH_BYTES - 1] & 0xF) != 0 {
            return Err(TxHashError::BadZeroBits);
        }

        Ok(Self(bytes))
    }

    /// Constructs a `TransactionHash` based on the given SHA3-256 hash.
    pub fn from_hash(hash: sha3_256::Hash) -> Self {
        let mut chunk = (*hash).first_chunk::<TX_HASH_LENGTH_BYTES>().unwrap().clone();
        chunk[TX_HASH_LENGTH_BYTES - 1] &= 0xF0;
        Self::from_slice(&chunk).unwrap()
    }
}

impl Placeholder for TxHash {
    fn placeholder_indexed(index: u64) -> Self {
        Self::from_hash(sha3_256::digest(&index.to_le_bytes()))
    }
}

impl fmt::Display for TxHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Encode the binary data as hex, and add the prefix character.
        // The buffer is one character larger than necessary because of the trailing four zero bits.
        let mut chars = [0u8; {TX_HASH_LENGTH + 1}];
        chars[0] = TX_PREPEND;
        hex::encode_to_slice(self.0, &mut chars[1..]).unwrap();
        f.write_str(from_utf8(&chars[0..TX_HASH_LENGTH]).unwrap())
    }
}

impl fmt::Debug for TxHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TxHash")
            .field(&self.to_string())
            .finish()
    }
}

impl FromStr for TxHash {
    type Err = TxHashError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() != TX_HASH_LENGTH {
            return Err(TxHashError::InvalidStringLength(input.to_string()));
        } else if input.as_bytes()[0] != TX_PREPEND {
            return Err(TxHashError::InvalidPrefix(input.to_string()));
        }

        // Strip the leading TX_PREPEND character, and then pad the string by adding an
        // additional trailing '0' character so that the hex string is parseable.
        let mut chars = [0u8; TX_HASH_LENGTH];
        *chars.first_chunk_mut::<{TX_HASH_LENGTH - 1}>().unwrap() = input.as_bytes()[1..].try_into().unwrap();
        chars[TX_HASH_LENGTH - 1] = '0' as u8;

        // Parse the hex string
        let mut bytes = [0u8; TX_HASH_LENGTH_BYTES];
        hex::decode_to_slice(&chars, &mut bytes)
            .map_err(|e| TxHashError::InvalidHexData(input.to_string(), e))?;
        Self::from_slice(&bytes)
    }
}

impl AsRef<[u8]> for TxHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for TxHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        assert!(serializer.is_human_readable(), "serializer must be human-readable!");

        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for TxHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        assert!(deserializer.is_human_readable(), "deserializer must be human-readable!");

        let text : String = serde::Deserialize::deserialize(deserializer)?;
        text.parse().map_err(<D::Error as serde::de::Error>::custom)
    }
}

/// An outpoint - a combination of a transaction hash and an index n into its vout
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize, Encode, Decode)]
pub struct OutPoint {
    pub t_hash: TxHash,
    pub n: u32,
}

impl OutPoint {
    /// Creates a new outpoint instance
    #[deprecated = "Use new_from_hash"]
    pub fn new(t_hash: String, n: i32) -> OutPoint {
        OutPoint {
            t_hash: t_hash.parse()
                .expect(&format!("Failed to parse transaction hash \"{}\"", t_hash)),
            n: n.try_into().expect("negative OutPoint index?!?"),
        }
    }

    /// Creates a new outpoint instance
    pub fn new_from_hash(t_hash: TxHash, n: u32) -> OutPoint {
        OutPoint { t_hash, n, }
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.t_hash, self.n)
    }
}

impl Placeholder for OutPoint {
    fn placeholder_indexed(index: u64) -> Self {
        OutPoint {
            t_hash: TxHash::placeholder_indexed(index),
            n: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TxInConstructor<'a> {
    Coinbase {
        block_number: u64,
    },
    Create {
        block_number: u64,
        asset: &'a Asset,
        public_key: &'a PublicKey,
        secret_key: &'a SecretKey,
    },
    P2PKH {
        previous_out: &'a OutPoint,
        public_key: &'a PublicKey,
        secret_key: &'a SecretKey,
    },
}

/// A Coinbase transaction input.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub struct CoinbaseTxIn {
    pub block_number: u64,
}

/// An asset creation transaction input.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub struct CreateTxIn {
    pub block_number: u64,
    pub asset_hash: Vec<u8>, // TODO: use a fixed-length type? // TODO: should we even keep this?
    pub public_key: PublicKey,
    pub signature: Signature,
}

/// A P2PKH redeem transaction input.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub struct P2PKHTxIn {
    pub previous_out: OutPoint,
    pub public_key: PublicKey,
    pub signature: Signature,
}

/// A generic transaction input.
/// This can any of the supported kinds of transaction inputs.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub enum TxIn {
    Coinbase(CoinbaseTxIn),
    Create(CreateTxIn),
    P2PKH(P2PKHTxIn),
}

impl TxIn {
    /// If this TxIn redeems a previous transaction output, gets the `OutPoint` referencing the
    /// redeemed transaction.
    pub fn find_previous_out(&self) -> Option<&OutPoint> {
        match self {
            TxIn::Coinbase(_) => None,
            TxIn::Create(_) => None,
            TxIn::P2PKH(p2pkh) => Some(&p2pkh.previous_out),
        }
    }

    /// Identifies which sort of transaction input this is.
    pub fn sort(&self) -> TxInSort {
        match self {
            TxIn::Coinbase(_) => TxInSort::Coinbase,
            TxIn::Create(_) => TxInSort::Create,
            TxIn::P2PKH(_) => TxInSort::P2PKH,
        }
    }
}

make_trivial_enum!(
#[doc = "The different kinds of transaction inputs."]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxInSort {
    Coinbase,
    Create,
    P2PKH,
}
all_variants=ALL_SORTS);

/// An error which can occur when trying to convert a TxIn to a specific subtype.
#[derive(Debug)]
pub struct TxInConversionError {
    pub expected: TxInSort,
    pub found: TxInSort,
}

impl std::error::Error for TxInConversionError {}

impl fmt::Display for TxInConversionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "wrong TxIn type: expected {:?}, found {:?}", self.expected, self.found)
    }
}

impl<'a> TryFrom<&'a TxIn> for &'a CoinbaseTxIn {
    type Error = TxInConversionError;

    fn try_from(value: &'a TxIn) -> Result<Self, Self::Error> {
        match value {
            TxIn::Coinbase(coinbase) => Ok(coinbase),
            _ => Err(TxInConversionError {
                expected: TxInSort::Coinbase,
                found: value.sort(),
            }),
        }
    }
}

impl<'a> TryFrom<&'a TxIn> for &'a CreateTxIn {
    type Error = TxInConversionError;

    fn try_from(value: &'a TxIn) -> Result<Self, Self::Error> {
        match value {
            TxIn::Create(create) => Ok(create),
            _ => Err(TxInConversionError {
                expected: TxInSort::Create,
                found: value.sort(),
            }),
        }
    }
}

impl<'a> TryFrom<&'a TxIn> for &'a P2PKHTxIn {
    type Error = TxInConversionError;

    fn try_from(value: &'a TxIn) -> Result<Self, Self::Error> {
        match value {
            TxIn::P2PKH(p2pkh) => Ok(p2pkh),
            _ => Err(TxInConversionError {
                expected: TxInSort::P2PKH,
                found: value.sort(),
                }),
        }
    }
}

/// An output of a transaction. It contains the public key that the next input
/// must be able to sign with to claim it. It also contains the block hash for the
/// potential DRS if this is a data asset transaction
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct TxOut {
    pub value: Asset,
    pub locktime: u64,
    pub script_public_key: AnyAddress,
}

impl TxOut {
    pub fn new_token_amount(to_address: AnyAddress, amount: TokenAmount, locktime: Option<u64>) -> TxOut {
        Self::new_asset(to_address, Asset::Token(amount), locktime)
    }

    /// Creates a new TxOut instance for a `Item` asset
    ///
    /// **NOTE:** Only create transactions may have `Item` assets that have a `None` `genesis_hash`
    pub fn new_item_amount(to_address: AnyAddress, item: ItemAsset, locktime: Option<u64>) -> TxOut {
        Self::new_asset(to_address, Asset::Item(item), locktime)
    }

    //TODO: Add handling for `Data' asset variant
    pub fn new_asset(to_address: AnyAddress, asset: Asset, locktime: Option<u64>) -> TxOut {
        assert!(matches!(asset, Asset::Item(_) | Asset::Token(_)),
                "Cannot create TxOut for asset of type {:?}", asset);
        TxOut {
            value: asset,
            locktime: locktime.unwrap_or(ZERO as u64),
            script_public_key: to_address,
        }
    }
}

impl Serialize for TxOut {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        assert!(serializer.is_human_readable(), "serializer must be human-readable!");

        let mut state = Serializer::serialize_struct(serializer, "TxOut", false as usize + 1 + 1 + 1)?;
        state.serialize_field("value", &self.value)?;
        state.serialize_field("locktime", &self.locktime)?;

        let script_public_key = match &self.script_public_key {
            AnyAddress::P2PKH(_) => Some(self.script_public_key.to_string()),
            AnyAddress::Burn => None,
        };
        state.serialize_field("script_public_key", &script_public_key)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for TxOut {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        assert!(deserializer.is_human_readable(), "deserializer must be human-readable!");

        #[derive(Deserialize)]
        struct JsonTxOut {
            value: Asset,
            locktime: u64,
            script_public_key: Option<String>,
        }

        let json : JsonTxOut = serde::Deserialize::deserialize(deserializer)?;
        Ok(TxOut {
            value: json.value,
            locktime: json.locktime,
            script_public_key: match json.script_public_key {
                None => AnyAddress::Burn,
                Some(address) => address.parse().map_err(<D::Error as serde::de::Error>::custom)?,
            }
        })
    }
}

make_error_type!(
#[doc = "An error which can occur while processing a transaction"]
pub enum TransactionError {
    BadVersion(version: TxVersion); "Unknown or unsupported transaction version: {version}",
    BadData; "Failed to deserialize transaction",
    V6Serialize(cause: v6::ToV6Error); "Failed to serialize v6 transaction: {cause}"; cause,
    V6Deserialize(cause: v6::FromV6Error); "Failed to deserialize v6 transaction: {cause}"; cause,
});

/// The basic transaction that is broadcasted on the network and contained in
/// blocks. A transaction can contain multiple inputs and outputs.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Transaction {
    pub version: TxVersion,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub fees: Vec<TxOut>,
    pub druid_info: Option<DdeValues>,
}

impl Transaction {
    /// Gets the create asset assigned to this transaction, if it exists
    fn get_create_asset(&self) -> Option<&Asset> {
        let is_create = self.inputs.len() == 1
            && self.inputs[0].find_previous_out().is_none()
            && self.outputs.len() == 1;

        is_create.then(|| &self.outputs[0].value)
    }

    /// Returns whether current transaction is a coinbase tx
    pub fn is_coinbase(&self) -> bool {
        self.get_create_asset()
            .map(|a| a.is_token())
            .unwrap_or_default()
    }

    /// Returns whether current transaction creates a new asset
    pub fn is_create_tx(&self) -> bool {
        self.get_create_asset()
            .map(|a| !a.is_token())
            .unwrap_or_default()
    }

    /// Serializes this transaction
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        match self.version {
            TxVersion::V6 => v6::serialize(self).map_err(TransactionError::V6Serialize),
            version => Err(TransactionError::BadVersion(version)),
        }
    }

    /// Deserializes a transaction from the given bytes
    ///
    /// ### Arguments
    ///
    /// * `bytes`   - a slice containing the serialized transaction
    pub fn deserialize(bytes: &[u8]) -> Result<Transaction, TransactionError> {
        match bytes.first() {
            Some(0) => v6::deserialize(bytes).map_err(TransactionError::V6Deserialize),
            Some(_) => Err(TransactionError::BadData),
            None => Err(TransactionError::BadData),
        }
    }
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use crate::primitives::address::P2PKHAddress;
    use crate::utils::serialize_utils::{bincode_decode_from_slice_standard_full, bincode_encode_to_vec_standard};
    use super::*;

    #[test]
    fn test_tx_hash_string() {
        let hash = TxHash::placeholder();
        let string = hash.to_string();
        assert_eq!(string, "g48dda5bbe9171a6656206ec56c595c5");
        assert_eq!(TxHash::from_str(&string).unwrap(), hash);
    }

    #[test]
    fn test_tx_hash_debug() {
        let hash = TxHash::placeholder();
        let debug = format!("{hash:?}");
        assert_eq!(debug, "TxHash(\"g48dda5bbe9171a6656206ec56c595c5\")");
    }

    #[test]
    fn test_tx_hash_slice() {
        let hash = TxHash::placeholder();
        let bytes = hash.as_ref().to_vec();
        assert_eq!(hex::encode(&bytes), "48dda5bbe9171a6656206ec56c595c50");
        assert_eq!(TxHash::from_slice(&bytes).unwrap(), hash);
    }

    #[test]
    fn test_tx_hash_bincode() {
        let hash = TxHash::placeholder();

        let serialized = bincode_encode_to_vec_standard(&hash).unwrap();
        assert_eq!(&serialized, hash.as_ref());
        let deserialized: TxHash = bincode_decode_from_slice_standard_full(&serialized).unwrap();
        assert_eq!(deserialized, hash);
    }

    #[test]
    fn test_tx_hash_serdejson() {
        let hash = TxHash::placeholder();
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, "\"g48dda5bbe9171a6656206ec56c595c5\"");
        assert_eq!(serde_json::from_str::<TxHash>(&json).unwrap(), hash);
    }

    #[test]
    fn test_tx_out_bincode() {
        let tx_out = TxOut {
            value: Asset::Token(TokenAmount(1337)),
            locktime: 123,
            script_public_key: AnyAddress::P2PKH(P2PKHAddress::placeholder()),
        };
        let serialized = bincode_encode_to_vec_standard(&tx_out).unwrap();
        assert_eq!(hex::encode(&serialized), "00fb39057b0148dda5bbe9171a6656206ec56c595c5834b6cf38c5fe71bcb44fe43833aee9df");
        let deserialized : TxOut = bincode_decode_from_slice_standard_full(&serialized).unwrap();
        assert_eq!(deserialized, tx_out);

        let tx_out = TxOut {
            value: Asset::Token(TokenAmount(1337)),
            locktime: 123,
            script_public_key: AnyAddress::Burn,
        };
        let serialized = bincode_encode_to_vec_standard(&tx_out).unwrap();
        assert_eq!(hex::encode(&serialized), "00fb39057b00");
        let deserialized : TxOut = bincode_decode_from_slice_standard_full(&serialized).unwrap();
        assert_eq!(deserialized, tx_out);
    }

    #[test]
    fn test_tx_out_serdejson() {
        let tx_out = TxOut {
            value: Asset::Token(TokenAmount(1337)),
            locktime: 123,
            script_public_key: AnyAddress::P2PKH(P2PKHAddress::placeholder()),
        };
        let json = serde_json::to_string(&tx_out).unwrap();
        assert_eq!(json, "{\"value\":{\"Token\":1337},\"locktime\":123,\"script_public_key\":\"48dda5bbe9171a6656206ec56c595c5834b6cf38c5fe71bcb44fe43833aee9df\"}");
        assert_eq!(serde_json::from_str::<TxOut>(&json).unwrap(), tx_out);

        let tx_out = TxOut {
            value: Asset::Token(TokenAmount(1337)),
            locktime: 123,
            script_public_key: AnyAddress::Burn,
        };
        let json = serde_json::to_string(&tx_out).unwrap();
        assert_eq!(json, "{\"value\":{\"Token\":1337},\"locktime\":123,\"script_public_key\":null}");
        assert_eq!(serde_json::from_str::<TxOut>(&json).unwrap(), tx_out);
        assert_eq!(serde_json::from_str::<TxOut>("{\"value\":{\"Token\":1337},\"locktime\":123}").unwrap(), tx_out);
    }
}
