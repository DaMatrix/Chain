#![allow(unused)]

use std::convert::TryInto;
use crate::constants::*;
use crate::crypto::sign_ed25519::{PublicKey, Signature};
use crate::primitives::{
    asset::{Asset, ItemAsset, TokenAmount},
    druid::{DdeValues, DruidExpectation},
};
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
use crate::utils::{FromOrdinal, is_valid_amount, Placeholder, ToOrdinal};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::{from_utf8, FromStr};
use bincode::{Decode, Encode, impl_borrow_decode};
use bincode::de::Decoder;
use bincode::enc::Encoder;
use bincode::enc::write::Writer;
use bincode::error::{AllowedEnumVariants, DecodeError, EncodeError};
use crate::crypto::sha3_256;
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
pub struct TxConstructor {
    pub previous_out: OutPoint,
    pub signatures: Vec<Signature>,
    pub pub_keys: Vec<PublicKey>,
}

const TX_HASH_LENGTH_BYTES : usize = TX_HASH_LENGTH / 2;

/// Compact transaction hash representation.
///
/// For legacy reasons, this wraps 31 hexadecimal digits worth of data, equivalent to 15.5 bytes.
/// Because of this, the 4 least significant bits of the last byte are unused. While awkward, this
/// actually means we have a convenient location to squeeze in a version indicator if we decide to
/// extend the transaction hash size in the future.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Encode, Decode)]
pub struct TxHash([u8; TX_HASH_LENGTH_BYTES]);

make_error_type!(pub enum TxHashError {
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
        self.0.as_ref()
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
    pub t_hash: String,
    pub n: i32,
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "t_hash:{}-n:{}", self.t_hash, self.n)
    }
}

impl OutPoint {
    /// Creates a new outpoint instance
    pub fn new(t_hash: String, n: i32) -> OutPoint {
        OutPoint { t_hash, n }
    }
}

impl Default for OutPoint {
    fn default() -> Self {
        Self::new(String::new(), 0)
    }
}

/// An input of a transaction. It contains the location of the previous
/// transaction's output that it claims and a signature that matches the
/// output's public key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct TxIn {
    pub previous_out: Option<OutPoint>,
    pub script_signature: Script,
}

impl Default for TxIn {
    fn default() -> Self {
        Self::new()
    }
}

impl TxIn {
    /// Creates a new TxIn instance
    pub fn new() -> TxIn {
        let mut script_sig = Script::new();
        script_sig.stack.push(StackEntry::Op(OpCodes::OP_0));

        TxIn {
            previous_out: None,
            script_signature: script_sig,
        }
    }

    /// Creates a new TxIn instance from provided script and no previous_out
    ///
    /// ### Arguments
    ///
    /// * `script_sig`      - Script signature of the previous outpoint
    pub fn new_from_script(script_sig: Script) -> TxIn {
        TxIn {
            previous_out: None,
            script_signature: script_sig,
        }
    }

    /// Creates a new TxIn instance from provided inputs
    ///
    /// ### Arguments
    ///
    /// * `previous_out`    - OutPoint of the previous transaction
    /// * `script_sig`      - Script signature of the previous outpoint
    pub fn new_from_input(previous_out: OutPoint, script_sig: Script) -> TxIn {
        TxIn {
            previous_out: Some(previous_out),
            script_signature: script_sig,
        }
    }
}

/// An output of a transaction. It contains the public key that the next input
/// must be able to sign with to claim it. It also contains the block hash for the
/// potential DRS if this is a data asset transaction
#[derive(Default, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct TxOut {
    pub value: Asset,
    pub locktime: u64,
    pub script_public_key: Option<String>,
}

impl TxOut {
    /// Creates a new TxOut instance
    pub fn new() -> TxOut {
        Default::default()
    }

    pub fn new_token_amount(
        to_address: String,
        amount: TokenAmount,
        locktime: Option<u64>,
    ) -> TxOut {
        TxOut {
            value: Asset::Token(amount),
            locktime: locktime.unwrap_or(ZERO as u64),
            script_public_key: Some(to_address),
        }
    }

    /// Creates a new TxOut instance for a `Item` asset
    ///
    /// **NOTE:** Only create transactions may have `Item` assets that have a `None` `genesis_hash`
    pub fn new_item_amount(to_address: String, item: ItemAsset, locktime: Option<u64>) -> TxOut {
        TxOut {
            value: Asset::Item(item),
            locktime: locktime.unwrap_or(ZERO as u64),
            script_public_key: Some(to_address),
        }
    }

    //TODO: Add handling for `Data' asset variant
    pub fn new_asset(to_address: String, asset: Asset, locktime: Option<u64>) -> TxOut {
        match asset {
            Asset::Token(amount) => TxOut::new_token_amount(to_address, amount, locktime),
            Asset::Item(item) => TxOut::new_item_amount(to_address, item, locktime),
            _ => panic!("Cannot create TxOut for asset of type {:?}", asset),
        }
    }

    /// Returns whether current tx_out is a P2SH
    pub fn is_p2sh_tx_out(&self) -> bool {
        if let Some(pk) = &self.script_public_key {
            let pk_bytes = pk.as_bytes();
            return pk_bytes[0] == P2SH_PREPEND;
        }

        false
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

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Transaction {
    /// Creates a new Transaction instance
    #[deprecated = "Transactions should not be used in a mutable fashion"]
    pub fn new() -> Transaction {
        Transaction {
            version: TxVersion::V6,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fees: Vec::new(),
            druid_info: None,
        }
    }

    /// Gets the create asset assigned to this transaction, if it exists
    fn get_create_asset(&self) -> Option<&Asset> {
        let is_create = self.inputs.len() == 1
            && self.inputs[0].previous_out.is_none()
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

    /// Returns whether current transaction is a P2SH tx
    pub fn is_p2sh_tx(&self) -> bool {
        if self.outputs.len() != 1 {
            return false;
        }

        if let Some(pk) = &self.outputs[0].script_public_key {
            let pk_bytes = pk.as_bytes();
            return pk_bytes[0] == P2SH_PREPEND;
        }

        false
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
    use super::*;

    #[test]
    fn test_tx_hash_string() {
        let hash = TxHash::placeholder();
        let string = hash.to_string();
        assert_eq!(string, "g48dda5bbe9171a6656206ec56c595c5");
        assert_eq!(TxHash::from_str(&string).unwrap(), hash);
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
        let config = bincode::config::standard();
        let hash = TxHash::placeholder();

        let serialized = bincode::encode_to_vec(&hash, config.clone()).unwrap();
        assert_eq!(&serialized, hash.as_ref());
        let deserialized: TxHash = bincode::decode_from_slice(&serialized, config.clone()).unwrap().0;
        assert_eq!(deserialized, hash);
    }

    #[test]
    fn test_tx_hash_serdejson() {
        let hash = TxHash::placeholder();
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(json, "\"g48dda5bbe9171a6656206ec56c595c5\"");
        assert_eq!(serde_json::from_str::<TxHash>(&json).unwrap(), hash);
    }
}
