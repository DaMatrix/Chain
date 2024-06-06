use std::convert::TryInto;
use bincode::Options;
use serde::{Deserialize, Serialize};
use crate::crypto::sign_ed25519::{PublicKey, Signature};
use crate::primitives::asset::{Asset, ItemAsset, TokenAmount};
use crate::primitives::druid::{DdeValues, DruidExpectation};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6PublicKey(
        #[serde(serialize_with = "<[_]>::serialize")]
        #[serde(deserialize_with = "v6_deserialize_slice")]
        [u8; 32]
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6Signature(
        #[serde(serialize_with = "<[_]>::serialize")]
        #[serde(deserialize_with = "v6_deserialize_slice")]
        [u8; 64]
);

fn v6_deserialize_slice<'de, D: serde::Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let value: &[u8] = serde::Deserialize::deserialize(deserializer)?;
    value
        .try_into()
        .map_err(|_| serde::de::Error::custom("Invalid array in deserialization".to_string()))
}

/// An outpoint - a combination of a transaction hash and an index n into its vout
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6OutPoint {
    t_hash: String,
    n: i32,
}

/// An input of a transaction. It contains the location of the previous
/// transaction's output that it claims and a signature that matches the
/// output's public key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6TxIn {
    previous_out: Option<V6OutPoint>,
    script_signature: V6Script, //TODO: maybe copy this in?
}

/// An output of a transaction. It contains the public key that the next input
/// must be able to sign with to claim it. It also contains the block hash for the
/// potential DRS if this is a data asset transaction
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6TxOut {
    value: V6Asset,
    locktime: u64,
    script_public_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6Transaction {
    inputs: Vec<V6TxIn>,
    outputs: Vec<V6TxOut>,
    version: usize,
    fees: Vec<V6TxOut>,
    druid_info: Option<V6DdeValues>,
}

/// The expectation to be met in a specific DRUID transaction
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6DruidExpectation {
    from: String,
    to: String,
    asset: V6Asset,
}

/// A structure to hold DDE-specific content in a transaction
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6DdeValues {
    druid: String,
    participants: usize,
    expectations: Vec<V6DruidExpectation>,
    genesis_hash: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6TokenAmount(u64);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6ItemAsset {
    amount: u64,
    genesis_hash: Option<String>,
    metadata: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum V6Asset {
    Token(V6TokenAmount),
    Item(V6ItemAsset),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6Script {
    stack: Vec<V6StackEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum V6StackEntry {
    Op(V6OpCodes),
    Signature(V6Signature),
    PubKey(V6PublicKey),
    Num(u64),
    Bytes(String),
}

// Ironically, the assigned opcode numbers are actually completely ignored by serde :)
// I'm still keeping them here for consistency, though.
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum V6OpCodes {
    // constants
    OP_0 = 0x00,
    OP_1 = 0x01,
    OP_2 = 0x02,
    OP_3 = 0x03,
    OP_4 = 0x04,
    OP_5 = 0x05,
    OP_6 = 0x06,
    OP_7 = 0x07,
    OP_8 = 0x08,
    OP_9 = 0x09,
    OP_10 = 0x0a,
    OP_11 = 0x0b,
    OP_12 = 0x0c,
    OP_13 = 0x0d,
    OP_14 = 0x0e,
    OP_15 = 0x0f,
    OP_16 = 0x10,
    // flow control
    OP_NOP = 0x20,
    OP_IF = 0x21,
    OP_NOTIF = 0x22,
    OP_ELSE = 0x23,
    OP_ENDIF = 0x24,
    OP_VERIFY = 0x25,
    OP_BURN = 0x26,
    // stack
    OP_TOALTSTACK = 0x30,
    OP_FROMALTSTACK = 0x31,
    OP_2DROP = 0x32,
    OP_2DUP = 0x33,
    OP_3DUP = 0x34,
    OP_2OVER = 0x35,
    OP_2ROT = 0x36,
    OP_2SWAP = 0x37,
    OP_IFDUP = 0x38,
    OP_DEPTH = 0x39,
    OP_DROP = 0x3a,
    OP_DUP = 0x3b,
    OP_NIP = 0x3c,
    OP_OVER = 0x3d,
    OP_PICK = 0x3e,
    OP_ROLL = 0x3f,
    OP_ROT = 0x40,
    OP_SWAP = 0x41,
    OP_TUCK = 0x42,
    // splice
    OP_CAT = 0x50,
    OP_SUBSTR = 0x51,
    OP_LEFT = 0x52,
    OP_RIGHT = 0x53,
    OP_SIZE = 0x54,
    // bitwise logic
    OP_INVERT = 0x60,
    OP_AND = 0x61,
    OP_OR = 0x62,
    OP_XOR = 0x63,
    OP_EQUAL = 0x64,
    OP_EQUALVERIFY = 0x65,
    // arithmetic
    OP_1ADD = 0x70,
    OP_1SUB = 0x71,
    OP_2MUL = 0x72,
    OP_2DIV = 0x73,
    OP_NOT = 0x74,
    OP_0NOTEQUAL = 0x75,
    OP_ADD = 0x76,
    OP_SUB = 0x77,
    OP_MUL = 0x78,
    OP_DIV = 0x79,
    OP_MOD = 0x7a,
    OP_LSHIFT = 0x7b,
    OP_RSHIFT = 0x7c,
    OP_BOOLAND = 0x7d,
    OP_BOOLOR = 0x7e,
    OP_NUMEQUAL = 0x7f,
    OP_NUMEQUALVERIFY = 0x80,
    OP_NUMNOTEQUAL = 0x81,
    OP_LESSTHAN = 0x82,
    OP_GREATERTHAN = 0x83,
    OP_LESSTHANOREQUAL = 0x84,
    OP_GREATERTHANOREQUAL = 0x85,
    OP_MIN = 0x86,
    OP_MAX = 0x87,
    OP_WITHIN = 0x88,
    // crypto
    OP_SHA3 = 0x90,
    OP_HASH256 = 0x91,
    OP_HASH256_V0 = 0x92,
    OP_HASH256_TEMP = 0x93,
    OP_CHECKSIG = 0x94,
    OP_CHECKSIGVERIFY = 0x95,
    OP_CHECKMULTISIG = 0x96,
    OP_CHECKMULTISIGVERIFY = 0x97,
    // smart data
    OP_CREATE = 0xa0,
    // reserved
    OP_NOP1 = 0xb0,
    OP_NOP2 = 0xb1,
    OP_NOP3 = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
}

macro_rules! bincode_options { () => {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}; }

make_error_type!(pub enum FromV6Error {
    BadVersion(version: u64); "not a v6 transaction: {version}",
    BadOpcode(name: &'static str); "script contained unsupported opcode \"{name}\"",
    NotHexBytes(bytes: String, cause: hex::FromHexError);
        "script contained invalid hex bytes: \"{bytes}\": {cause}"; cause,
    Deserialize(cause: bincode::Error);
        "failed to deserialize v6 transaction: {cause}"; cause,
});

fn upgrade_v6_asset(old: &V6Asset) -> Result<Asset, FromV6Error> {
    match old {
        V6Asset::Token(V6TokenAmount(amount)) => Ok(Asset::Token(TokenAmount(*amount))),
        V6Asset::Item(V6ItemAsset { amount, genesis_hash, metadata, }) =>
            Ok(Asset::Item(ItemAsset {
                amount: *amount,
                genesis_hash: genesis_hash.clone(),
                metadata: metadata.clone(),
            })),
    }
}

fn upgrade_v6_script(old: &V6Script) -> Result<Script, FromV6Error> {
    Ok(Script::from(old.stack.iter()
        .map(|entry| match entry {
            V6StackEntry::Op(op) => match op {
                V6OpCodes::OP_0 => Ok(OpCodes::OP_0),
                V6OpCodes::OP_1 => Ok(OpCodes::OP_1),
                V6OpCodes::OP_2 => Ok(OpCodes::OP_2),
                V6OpCodes::OP_3 => Ok(OpCodes::OP_3),
                V6OpCodes::OP_4 => Ok(OpCodes::OP_4),
                V6OpCodes::OP_5 => Ok(OpCodes::OP_5),
                V6OpCodes::OP_6 => Ok(OpCodes::OP_6),
                V6OpCodes::OP_7 => Ok(OpCodes::OP_7),
                V6OpCodes::OP_8 => Ok(OpCodes::OP_8),
                V6OpCodes::OP_9 => Ok(OpCodes::OP_9),
                V6OpCodes::OP_10 => Ok(OpCodes::OP_10),
                V6OpCodes::OP_11 => Ok(OpCodes::OP_11),
                V6OpCodes::OP_12 => Ok(OpCodes::OP_12),
                V6OpCodes::OP_13 => Ok(OpCodes::OP_13),
                V6OpCodes::OP_14 => Ok(OpCodes::OP_14),
                V6OpCodes::OP_15 => Ok(OpCodes::OP_15),
                V6OpCodes::OP_16 => Ok(OpCodes::OP_16),
                V6OpCodes::OP_NOP => Ok(OpCodes::OP_NOP),
                V6OpCodes::OP_IF => Ok(OpCodes::OP_IF),
                V6OpCodes::OP_NOTIF => Ok(OpCodes::OP_NOTIF),
                V6OpCodes::OP_ELSE => Ok(OpCodes::OP_ELSE),
                V6OpCodes::OP_ENDIF => Ok(OpCodes::OP_ENDIF),
                V6OpCodes::OP_VERIFY => Ok(OpCodes::OP_VERIFY),
                V6OpCodes::OP_BURN => Ok(OpCodes::OP_BURN),
                V6OpCodes::OP_TOALTSTACK => Ok(OpCodes::OP_TOALTSTACK),
                V6OpCodes::OP_FROMALTSTACK => Ok(OpCodes::OP_FROMALTSTACK),
                V6OpCodes::OP_2DROP => Ok(OpCodes::OP_2DROP),
                V6OpCodes::OP_2DUP => Ok(OpCodes::OP_2DUP),
                V6OpCodes::OP_3DUP => Ok(OpCodes::OP_3DUP),
                V6OpCodes::OP_2OVER => Ok(OpCodes::OP_2OVER),
                V6OpCodes::OP_2ROT => Ok(OpCodes::OP_2ROT),
                V6OpCodes::OP_2SWAP => Ok(OpCodes::OP_2SWAP),
                V6OpCodes::OP_IFDUP => Ok(OpCodes::OP_IFDUP),
                V6OpCodes::OP_DEPTH => Ok(OpCodes::OP_DEPTH),
                V6OpCodes::OP_DROP => Ok(OpCodes::OP_DROP),
                V6OpCodes::OP_DUP => Ok(OpCodes::OP_DUP),
                V6OpCodes::OP_NIP => Ok(OpCodes::OP_NIP),
                V6OpCodes::OP_OVER => Ok(OpCodes::OP_OVER),
                V6OpCodes::OP_PICK => Ok(OpCodes::OP_PICK),
                V6OpCodes::OP_ROLL => Ok(OpCodes::OP_ROLL),
                V6OpCodes::OP_ROT => Ok(OpCodes::OP_ROT),
                V6OpCodes::OP_SWAP => Ok(OpCodes::OP_SWAP),
                V6OpCodes::OP_TUCK => Ok(OpCodes::OP_TUCK),
                V6OpCodes::OP_CAT => Ok(OpCodes::OP_CAT),
                V6OpCodes::OP_SUBSTR => Ok(OpCodes::OP_SUBSTR),
                V6OpCodes::OP_LEFT => Ok(OpCodes::OP_LEFT),
                V6OpCodes::OP_RIGHT => Ok(OpCodes::OP_RIGHT),
                V6OpCodes::OP_SIZE => Ok(OpCodes::OP_SIZE),
                V6OpCodes::OP_INVERT => Ok(OpCodes::OP_INVERT),
                V6OpCodes::OP_AND => Ok(OpCodes::OP_AND),
                V6OpCodes::OP_OR => Ok(OpCodes::OP_OR),
                V6OpCodes::OP_XOR => Ok(OpCodes::OP_XOR),
                V6OpCodes::OP_EQUAL => Ok(OpCodes::OP_EQUAL),
                V6OpCodes::OP_EQUALVERIFY => Ok(OpCodes::OP_EQUALVERIFY),
                V6OpCodes::OP_1ADD => Ok(OpCodes::OP_1ADD),
                V6OpCodes::OP_1SUB => Ok(OpCodes::OP_1SUB),
                V6OpCodes::OP_2MUL => Ok(OpCodes::OP_2MUL),
                V6OpCodes::OP_2DIV => Ok(OpCodes::OP_2DIV),
                V6OpCodes::OP_NOT => Ok(OpCodes::OP_NOT),
                V6OpCodes::OP_0NOTEQUAL => Ok(OpCodes::OP_0NOTEQUAL),
                V6OpCodes::OP_ADD => Ok(OpCodes::OP_ADD),
                V6OpCodes::OP_SUB => Ok(OpCodes::OP_SUB),
                V6OpCodes::OP_MUL => Ok(OpCodes::OP_MUL),
                V6OpCodes::OP_DIV => Ok(OpCodes::OP_DIV),
                V6OpCodes::OP_MOD => Ok(OpCodes::OP_MOD),
                V6OpCodes::OP_LSHIFT => Ok(OpCodes::OP_LSHIFT),
                V6OpCodes::OP_RSHIFT => Ok(OpCodes::OP_RSHIFT),
                V6OpCodes::OP_BOOLAND => Ok(OpCodes::OP_BOOLAND),
                V6OpCodes::OP_BOOLOR => Ok(OpCodes::OP_BOOLOR),
                V6OpCodes::OP_NUMEQUAL => Ok(OpCodes::OP_NUMEQUAL),
                V6OpCodes::OP_NUMEQUALVERIFY => Ok(OpCodes::OP_NUMEQUALVERIFY),
                V6OpCodes::OP_NUMNOTEQUAL => Ok(OpCodes::OP_NUMNOTEQUAL),
                V6OpCodes::OP_LESSTHAN => Ok(OpCodes::OP_LESSTHAN),
                V6OpCodes::OP_GREATERTHAN => Ok(OpCodes::OP_GREATERTHAN),
                V6OpCodes::OP_LESSTHANOREQUAL => Ok(OpCodes::OP_LESSTHANOREQUAL),
                V6OpCodes::OP_GREATERTHANOREQUAL => Ok(OpCodes::OP_GREATERTHANOREQUAL),
                V6OpCodes::OP_MIN => Ok(OpCodes::OP_MIN),
                V6OpCodes::OP_MAX => Ok(OpCodes::OP_MAX),
                V6OpCodes::OP_WITHIN => Ok(OpCodes::OP_WITHIN),
                V6OpCodes::OP_SHA3 => Ok(OpCodes::OP_SHA3),
                V6OpCodes::OP_HASH256 => Ok(OpCodes::OP_HASH256),
                V6OpCodes::OP_HASH256_V0 => Err(FromV6Error::BadOpcode("OP_HASH256_V0")),
                V6OpCodes::OP_HASH256_TEMP => Err(FromV6Error::BadOpcode("OP_HASH256_TEMP")),
                V6OpCodes::OP_CHECKSIG => Ok(OpCodes::OP_CHECKSIG),
                V6OpCodes::OP_CHECKSIGVERIFY => Ok(OpCodes::OP_CHECKSIGVERIFY),
                V6OpCodes::OP_CHECKMULTISIG => Ok(OpCodes::OP_CHECKMULTISIG),
                V6OpCodes::OP_CHECKMULTISIGVERIFY => Ok(OpCodes::OP_CHECKMULTISIGVERIFY),
                V6OpCodes::OP_CREATE => Ok(OpCodes::OP_CREATE),
                V6OpCodes::OP_NOP1 => Ok(OpCodes::OP_NOP1),
                V6OpCodes::OP_NOP2 => Ok(OpCodes::OP_NOP2),
                V6OpCodes::OP_NOP3 => Ok(OpCodes::OP_NOP3),
                V6OpCodes::OP_NOP4 => Ok(OpCodes::OP_NOP4),
                V6OpCodes::OP_NOP5 => Ok(OpCodes::OP_NOP5),
                V6OpCodes::OP_NOP6 => Ok(OpCodes::OP_NOP6),
                V6OpCodes::OP_NOP7 => Ok(OpCodes::OP_NOP7),
                V6OpCodes::OP_NOP8 => Ok(OpCodes::OP_NOP8),
                V6OpCodes::OP_NOP9 => Ok(OpCodes::OP_NOP9),
                V6OpCodes::OP_NOP10 => Ok(OpCodes::OP_NOP10),
            }.map(StackEntry::Op),
            V6StackEntry::Signature(signature) =>
                Ok(StackEntry::Signature(Signature::from_slice(&signature.0).unwrap())),
            V6StackEntry::PubKey(pubkey) =>
                Ok(StackEntry::PubKey(PublicKey::from_slice(&pubkey.0).unwrap())),
            V6StackEntry::Num(num) =>
                Ok(StackEntry::Num((*num).try_into().unwrap())),
            V6StackEntry::Bytes(bytes) =>
                Ok(StackEntry::Bytes(hex::decode(bytes)
                    .map_err(|err| FromV6Error::NotHexBytes(bytes.clone(), err))?)),
        })
        .collect::<Result<Vec<_>, _>>()?))
}

fn upgrade_v6_outpoint(old: &V6OutPoint) -> Result<OutPoint, FromV6Error> {
    Ok(OutPoint {
        t_hash: old.t_hash.clone(),
        n: old.n,
    })
}

fn upgrade_v6_txin(old: &V6TxIn) -> Result<TxIn, FromV6Error> {
    Ok(TxIn {
        previous_out: old.previous_out.as_ref().map(upgrade_v6_outpoint).transpose()?,
        script_signature: upgrade_v6_script(&old.script_signature)?,
    })
}

fn upgrade_v6_txout(old: &V6TxOut) -> Result<TxOut, FromV6Error> {
    Ok(TxOut {
        value: upgrade_v6_asset(&old.value)?,
        locktime: old.locktime,
        script_public_key: old.script_public_key.clone(),
    })
}

fn upgrade_v6_druidexpectation(old: &V6DruidExpectation) -> Result<DruidExpectation, FromV6Error> {
    Ok(DruidExpectation {
        from: old.from.clone(),
        to: old.to.clone(),
        asset: upgrade_v6_asset(&old.asset)?,
    })
}

fn upgrade_v6_ddevalues(old: &V6DdeValues) -> Result<DdeValues, FromV6Error> {
    Ok(DdeValues {
        druid: old.druid.clone(),
        participants: old.participants,
        expectations: old.expectations.iter()
            .map(upgrade_v6_druidexpectation)
            .collect::<Result<Vec<_>, _>>()?,
        genesis_hash: old.genesis_hash.clone(),
    })
}

fn upgrade_v6_tx(old: &V6Transaction) -> Result<Transaction, FromV6Error> {
    if old.version != 6 {
        return Err(FromV6Error::BadVersion(old.version as u64));
    }
    
    Ok(Transaction {
        version: 6,
        inputs: old.inputs.iter().map(upgrade_v6_txin).collect::<Result<Vec<_>, _>>()?,
        outputs: old.outputs.iter().map(upgrade_v6_txout).collect::<Result<Vec<_>, _>>()?,
        fees: old.fees.iter().map(upgrade_v6_txout).collect::<Result<Vec<_>, _>>()?,
        druid_info: old.druid_info.as_ref().map(upgrade_v6_ddevalues).transpose()?,
    })
}

/// Tries to deserialize a v6 transaction into the new object representation.
///
/// ### Arguments
///
/// * `bytes`  - a slice containing the serialized v6 transaction
pub fn deserialize(bytes: &[u8]) -> Result<Transaction, FromV6Error> {
    bincode_options!()
        .deserialize::<V6Transaction>(bytes)
        .map_err(FromV6Error::Deserialize)
        .and_then(|tx| upgrade_v6_tx(&tx))
}

make_error_type!(pub enum ToV6Error {
    BadVersion(version: u64); "not a v6 transaction: {version}",
    BadOpcode(name: &'static str); "script contained unsupported opcode \"{name}\"",
    NotHexBytes(bytes: String, cause: hex::FromHexError);
        "script contained invalid hex bytes: \"{bytes}\": {cause}"; cause,
    Serialize(cause: bincode::Error);
        "failed to serialize v6 transaction: {cause}"; cause,
});

fn downgrade_v6_asset(old: &Asset) -> Result<V6Asset, ToV6Error> {
    match old {
        Asset::Token(TokenAmount(amount)) => Ok(V6Asset::Token(V6TokenAmount(*amount))),
        Asset::Item(ItemAsset { amount, genesis_hash, metadata, }) =>
            Ok(V6Asset::Item(V6ItemAsset {
                amount: *amount,
                genesis_hash: genesis_hash.clone(),
                metadata: metadata.clone(),
            })),
    }
}

fn downgrade_v6_script(old: &Script) -> Result<V6Script, ToV6Error> {
    Ok(V6Script {
        stack: old.stack.iter()
            .map(|entry| match entry {
                StackEntry::Op(op) => match op {
                    OpCodes::OP_0 => Ok(V6OpCodes::OP_0),
                    OpCodes::OP_1 => Ok(V6OpCodes::OP_1),
                    OpCodes::OP_2 => Ok(V6OpCodes::OP_2),
                    OpCodes::OP_3 => Ok(V6OpCodes::OP_3),
                    OpCodes::OP_4 => Ok(V6OpCodes::OP_4),
                    OpCodes::OP_5 => Ok(V6OpCodes::OP_5),
                    OpCodes::OP_6 => Ok(V6OpCodes::OP_6),
                    OpCodes::OP_7 => Ok(V6OpCodes::OP_7),
                    OpCodes::OP_8 => Ok(V6OpCodes::OP_8),
                    OpCodes::OP_9 => Ok(V6OpCodes::OP_9),
                    OpCodes::OP_10 => Ok(V6OpCodes::OP_10),
                    OpCodes::OP_11 => Ok(V6OpCodes::OP_11),
                    OpCodes::OP_12 => Ok(V6OpCodes::OP_12),
                    OpCodes::OP_13 => Ok(V6OpCodes::OP_13),
                    OpCodes::OP_14 => Ok(V6OpCodes::OP_14),
                    OpCodes::OP_15 => Ok(V6OpCodes::OP_15),
                    OpCodes::OP_16 => Ok(V6OpCodes::OP_16),
                    OpCodes::OP_NOP => Ok(V6OpCodes::OP_NOP),
                    OpCodes::OP_IF => Ok(V6OpCodes::OP_IF),
                    OpCodes::OP_NOTIF => Ok(V6OpCodes::OP_NOTIF),
                    OpCodes::OP_ELSE => Ok(V6OpCodes::OP_ELSE),
                    OpCodes::OP_ENDIF => Ok(V6OpCodes::OP_ENDIF),
                    OpCodes::OP_VERIFY => Ok(V6OpCodes::OP_VERIFY),
                    OpCodes::OP_BURN => Ok(V6OpCodes::OP_BURN),
                    OpCodes::OP_TOALTSTACK => Ok(V6OpCodes::OP_TOALTSTACK),
                    OpCodes::OP_FROMALTSTACK => Ok(V6OpCodes::OP_FROMALTSTACK),
                    OpCodes::OP_2DROP => Ok(V6OpCodes::OP_2DROP),
                    OpCodes::OP_2DUP => Ok(V6OpCodes::OP_2DUP),
                    OpCodes::OP_3DUP => Ok(V6OpCodes::OP_3DUP),
                    OpCodes::OP_2OVER => Ok(V6OpCodes::OP_2OVER),
                    OpCodes::OP_2ROT => Ok(V6OpCodes::OP_2ROT),
                    OpCodes::OP_2SWAP => Ok(V6OpCodes::OP_2SWAP),
                    OpCodes::OP_IFDUP => Ok(V6OpCodes::OP_IFDUP),
                    OpCodes::OP_DEPTH => Ok(V6OpCodes::OP_DEPTH),
                    OpCodes::OP_DROP => Ok(V6OpCodes::OP_DROP),
                    OpCodes::OP_DUP => Ok(V6OpCodes::OP_DUP),
                    OpCodes::OP_NIP => Ok(V6OpCodes::OP_NIP),
                    OpCodes::OP_OVER => Ok(V6OpCodes::OP_OVER),
                    OpCodes::OP_PICK => Ok(V6OpCodes::OP_PICK),
                    OpCodes::OP_ROLL => Ok(V6OpCodes::OP_ROLL),
                    OpCodes::OP_ROT => Ok(V6OpCodes::OP_ROT),
                    OpCodes::OP_SWAP => Ok(V6OpCodes::OP_SWAP),
                    OpCodes::OP_TUCK => Ok(V6OpCodes::OP_TUCK),
                    OpCodes::OP_CAT => Ok(V6OpCodes::OP_CAT),
                    OpCodes::OP_SUBSTR => Ok(V6OpCodes::OP_SUBSTR),
                    OpCodes::OP_LEFT => Ok(V6OpCodes::OP_LEFT),
                    OpCodes::OP_RIGHT => Ok(V6OpCodes::OP_RIGHT),
                    OpCodes::OP_SIZE => Ok(V6OpCodes::OP_SIZE),
                    OpCodes::OP_INVERT => Ok(V6OpCodes::OP_INVERT),
                    OpCodes::OP_AND => Ok(V6OpCodes::OP_AND),
                    OpCodes::OP_OR => Ok(V6OpCodes::OP_OR),
                    OpCodes::OP_XOR => Ok(V6OpCodes::OP_XOR),
                    OpCodes::OP_EQUAL => Ok(V6OpCodes::OP_EQUAL),
                    OpCodes::OP_EQUALVERIFY => Ok(V6OpCodes::OP_EQUALVERIFY),
                    OpCodes::OP_1ADD => Ok(V6OpCodes::OP_1ADD),
                    OpCodes::OP_1SUB => Ok(V6OpCodes::OP_1SUB),
                    OpCodes::OP_2MUL => Ok(V6OpCodes::OP_2MUL),
                    OpCodes::OP_2DIV => Ok(V6OpCodes::OP_2DIV),
                    OpCodes::OP_NOT => Ok(V6OpCodes::OP_NOT),
                    OpCodes::OP_0NOTEQUAL => Ok(V6OpCodes::OP_0NOTEQUAL),
                    OpCodes::OP_ADD => Ok(V6OpCodes::OP_ADD),
                    OpCodes::OP_SUB => Ok(V6OpCodes::OP_SUB),
                    OpCodes::OP_MUL => Ok(V6OpCodes::OP_MUL),
                    OpCodes::OP_DIV => Ok(V6OpCodes::OP_DIV),
                    OpCodes::OP_MOD => Ok(V6OpCodes::OP_MOD),
                    OpCodes::OP_LSHIFT => Ok(V6OpCodes::OP_LSHIFT),
                    OpCodes::OP_RSHIFT => Ok(V6OpCodes::OP_RSHIFT),
                    OpCodes::OP_BOOLAND => Ok(V6OpCodes::OP_BOOLAND),
                    OpCodes::OP_BOOLOR => Ok(V6OpCodes::OP_BOOLOR),
                    OpCodes::OP_NUMEQUAL => Ok(V6OpCodes::OP_NUMEQUAL),
                    OpCodes::OP_NUMEQUALVERIFY => Ok(V6OpCodes::OP_NUMEQUALVERIFY),
                    OpCodes::OP_NUMNOTEQUAL => Ok(V6OpCodes::OP_NUMNOTEQUAL),
                    OpCodes::OP_LESSTHAN => Ok(V6OpCodes::OP_LESSTHAN),
                    OpCodes::OP_GREATERTHAN => Ok(V6OpCodes::OP_GREATERTHAN),
                    OpCodes::OP_LESSTHANOREQUAL => Ok(V6OpCodes::OP_LESSTHANOREQUAL),
                    OpCodes::OP_GREATERTHANOREQUAL => Ok(V6OpCodes::OP_GREATERTHANOREQUAL),
                    OpCodes::OP_MIN => Ok(V6OpCodes::OP_MIN),
                    OpCodes::OP_MAX => Ok(V6OpCodes::OP_MAX),
                    OpCodes::OP_WITHIN => Ok(V6OpCodes::OP_WITHIN),
                    OpCodes::OP_SHA3 => Ok(V6OpCodes::OP_SHA3),
                    OpCodes::OP_HASH256 => Ok(V6OpCodes::OP_HASH256),
                    OpCodes::OP_CHECKSIG => Ok(V6OpCodes::OP_CHECKSIG),
                    OpCodes::OP_CHECKSIGVERIFY => Ok(V6OpCodes::OP_CHECKSIGVERIFY),
                    OpCodes::OP_CHECKMULTISIG => Ok(V6OpCodes::OP_CHECKMULTISIG),
                    OpCodes::OP_CHECKMULTISIGVERIFY => Ok(V6OpCodes::OP_CHECKMULTISIGVERIFY),
                    OpCodes::OP_CREATE => Ok(V6OpCodes::OP_CREATE),
                    OpCodes::OP_NOP1 => Ok(V6OpCodes::OP_NOP1),
                    OpCodes::OP_NOP2 => Ok(V6OpCodes::OP_NOP2),
                    OpCodes::OP_NOP3 => Ok(V6OpCodes::OP_NOP3),
                    OpCodes::OP_NOP4 => Ok(V6OpCodes::OP_NOP4),
                    OpCodes::OP_NOP5 => Ok(V6OpCodes::OP_NOP5),
                    OpCodes::OP_NOP6 => Ok(V6OpCodes::OP_NOP6),
                    OpCodes::OP_NOP7 => Ok(V6OpCodes::OP_NOP7),
                    OpCodes::OP_NOP8 => Ok(V6OpCodes::OP_NOP8),
                    OpCodes::OP_NOP9 => Ok(V6OpCodes::OP_NOP9),
                    OpCodes::OP_NOP10 => Ok(V6OpCodes::OP_NOP10),
                    OpCodes::OP_NOP11 => Err(ToV6Error::BadOpcode("OP_NOP11")),
                    OpCodes::OP_NOP12 => Err(ToV6Error::BadOpcode("OP_NOP12")),
                }.map(V6StackEntry::Op),
                StackEntry::Signature(signature) =>
                    Ok(V6StackEntry::Signature(V6Signature(signature.as_ref().try_into().unwrap()))),
                StackEntry::PubKey(pubkey) =>
                    Ok(V6StackEntry::PubKey(V6PublicKey(pubkey.as_ref().try_into().unwrap()))),
                StackEntry::Num(num) =>
                    Ok(V6StackEntry::Num((*num).try_into().unwrap())),
                StackEntry::Bytes(bytes) =>
                    Ok(V6StackEntry::Bytes(hex::encode(bytes))),
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn downgrade_v6_outpoint(old: &OutPoint) -> Result<V6OutPoint, ToV6Error> {
    Ok(V6OutPoint {
        t_hash: old.t_hash.clone(),
        n: old.n,
    })
}

fn downgrade_v6_txin(old: &TxIn) -> Result<V6TxIn, ToV6Error> {
    Ok(V6TxIn {
        previous_out: old.previous_out.as_ref().map(downgrade_v6_outpoint).transpose()?,
        script_signature: downgrade_v6_script(&old.script_signature)?,
    })
}

fn downgrade_v6_txout(old: &TxOut) -> Result<V6TxOut, ToV6Error> {
    Ok(V6TxOut {
        value: downgrade_v6_asset(&old.value)?,
        locktime: old.locktime,
        script_public_key: old.script_public_key.clone(),
    })
}

fn downgrade_v6_druidexpectation(old: &DruidExpectation) -> Result<V6DruidExpectation, ToV6Error> {
    Ok(V6DruidExpectation {
        from: old.from.clone(),
        to: old.to.clone(),
        asset: downgrade_v6_asset(&old.asset)?,
    })
}

fn downgrade_v6_ddevalues(old: &DdeValues) -> Result<V6DdeValues, ToV6Error> {
    Ok(V6DdeValues {
        druid: old.druid.clone(),
        participants: old.participants,
        expectations: old.expectations.iter()
            .map(downgrade_v6_druidexpectation)
            .collect::<Result<Vec<_>, _>>()?,
        genesis_hash: old.genesis_hash.clone(),
    })
}

fn downgrade_v6_tx(old: &Transaction) -> Result<V6Transaction, ToV6Error> {
    if old.version != 6 {
        return Err(ToV6Error::BadVersion(old.version as u64));
    }
    
    Ok(V6Transaction {
        version: 6,
        inputs: old.inputs.iter().map(downgrade_v6_txin).collect::<Result<Vec<_>, _>>()?,
        outputs: old.outputs.iter().map(downgrade_v6_txout).collect::<Result<Vec<_>, _>>()?,
        fees: old.fees.iter().map(downgrade_v6_txout).collect::<Result<Vec<_>, _>>()?,
        druid_info: old.druid_info.as_ref().map(downgrade_v6_ddevalues).transpose()?,
    })
}

/// Takes a v6 transaction in the new object representation and serializes it using the v6 format.
///
/// ### Arguments
///
/// * `tx`    - A v6 transaction in the new object representation
pub fn serialize(tx: &Transaction) -> Result<Vec<u8>, ToV6Error> {
    bincode_options!().serialize(&downgrade_v6_tx(tx)?).map_err(ToV6Error::Serialize)
}

/// Checks if a transaction meets all the requirements for upgrading to version 7, otherwise
/// it panics.
///
/// Aside from artificial transactions created in test code, this should always pass.
/*pub fn validate_v7_preconditions(tx: &Transaction) {
    use crate::constants::{STANDARD_ADDRESS_LENGTH_BYTES, TX_HASH_LENGTH};
    use crate::utils::{script_utils, transaction_utils};

    assert_eq!(tx.version, 6, "incorrect version {}: {:#?}", tx.version, tx);

    //verify that all strings have the correct length
    for tx_in in &tx.inputs {
        if let Some(prev_out) = &tx_in.previous_out {
            assert!(prev_out.t_hash.len() == TX_HASH_LENGTH
                        && prev_out.t_hash.as_bytes()[0] == 'g' as u8
                        && hex::decode(format!("{}0", prev_out.t_hash.get(1..).unwrap())).is_ok(),
                    "invalid transaction hash {}: {:#?}", prev_out.t_hash, tx);
            assert!(prev_out.n >= 0, "negative outpoint index {}: {:#?}", prev_out.n, tx);
        }

        let script = &tx_in.script_signature;
        if let Some(_) = script_utils::match_coinbase_script(script) {
            // Nothing
        } else if let Some((_, asset_hash, _, _)) = script_utils::match_create_script(script) {
            assert_eq!(asset_hash.len(), 32,
                       "CreateItem asset hash has invalid length {}: {:#?}", asset_hash.len(), tx);
        } else if let Some(
            (check_data, signature, public_key, public_key_hash)
        ) = script_utils::match_p2pkh_script(script) {
            let tx_in_signable_hash = transaction_utils::construct_tx_in_signable_hash(
                tx_in.previous_out.as_ref().unwrap());
            let tx_in_out_signable_hash = transaction_utils::construct_tx_in_out_signable_hash(
                tx_in, &tx.outputs);

            assert!(hex::encode(check_data) == tx_in_signable_hash
                        || hex::encode(check_data) == tx_in_out_signable_hash,
                    "P2PKH check_data doesn't match any known formats: {:#?}: {:#?}", tx_in, tx);

            assert_eq!(transaction_utils::construct_address(public_key),
                       hex::encode(public_key_hash),
                       "P2PKH public key doesn't match hash: {:#?}: {:#?}", tx_in, tx);
        } else {
            panic!("unknown TxIn script {:#?}: {:#?}", script.stack, tx);
        }
    }

    for tx_out in &tx.outputs {
        assert!(tx_out.script_public_key.is_some(),
                "TxOut destination address is None: {:#?}", tx);

        let address = tx_out.script_public_key.as_ref().unwrap();
        assert!(address.len() == STANDARD_ADDRESS_LENGTH && hex::decode(address).is_ok(),
                "Invalid address {}: {:#?}", address, tx);
    }
}*/

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use crate::constants::{STANDARD_ADDRESS_LENGTH_BYTES, TX_HASH_LENGTH};
    use crate::crypto::sign_ed25519;
    use crate::crypto::sign_ed25519::{PublicKey, SecretKey};
    use crate::primitives::asset::{Asset, AssetValues, ItemAsset, TokenAmount};
    use crate::primitives::transaction::{OutPoint, Transaction, TxConstructor, TxIn, TxOut};
    use crate::utils::{script_utils, transaction_utils};
    use crate::utils::transaction_utils::ReceiverInfo;

    fn test_construct_valid_inputs() -> (Vec<TxIn>, BTreeMap<OutPoint, (PublicKey, SecretKey)>) {
        let (_pk, sk) = sign_ed25519::gen_test_keypair(0);
        let (pk, _sk) = sign_ed25519::gen_test_keypair(1);
        let t_hash = [0u8; TX_HASH_LENGTH / 2];
        let prev_out = OutPoint::new(hex::encode(&t_hash), 0);

        let mut key_material = BTreeMap::new();
        key_material.insert(prev_out.clone(), (pk, sk));

        let tx_const = TxConstructor {
            previous_out: prev_out,
            signatures: vec![],
            pub_keys: vec![pk],
        };

        let tx_ins = transaction_utils::construct_payment_tx_ins(vec![tx_const]);
        (tx_ins, key_material)
    }

    fn test_tx_matches_expected(tx: &Transaction, expected_hex: &str) {
        let tx_ser = bincode::serialize(tx).unwrap();
        let tx_hex = hex::encode(&tx_ser);
        assert_eq!(tx_hex, expected_hex);

        let expected_ser = hex::decode(expected_hex).unwrap();
        let expected = bincode::deserialize::<Transaction>(&expected_ser).unwrap();
        assert_eq!(tx, &expected);
    }

    #[test]
    fn test_p2pkh_tx() {
        let tokens = TokenAmount(400000);
        let (tx_ins, key_material) = test_construct_valid_inputs();

        let payment_tx = transaction_utils::construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]),
                asset: Asset::Token(tokens),
            },
            None,
            0,
            &key_material,
        );

        assert_eq!(Asset::Token(tokens), payment_tx.outputs[0].value);
        assert_eq!(
            payment_tx.outputs[0].script_public_key,
            Some(hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]))
        );

        let tx_ins_spent = AssetValues::new(tokens, BTreeMap::new());
        assert!(script_utils::tx_outs_are_valid(
            &payment_tx.outputs,
            &payment_tx.fees,
            tx_ins_spent,
        ));

        let expected = "01000000000000000120000000000000003030303030303030303030303030303030303030303030303030303030303030000000000800000000000000040000002000000000000000b240449307b3f9df0bc8a044fdc7f7e73690d9f28b4cf2b9b0ea8d4b683c9f3b01000000e36e2eec1a039c3c5c5df5df16bbad369d7b534e101b986a374cfe52f8a8622fb0e58ec38f9bb890285385c6a719d41eb128f4661f9aeb21ccce85267f1c2e04020000002a698271b680fd389ca2dc4823a8084065b2554caf0753b5ddc57a750564b1d40000000023000000000000005000000004000000200000000000000041063307a3fd68f3b03839c2889cd7ad0ae06259cad1be96ea4d8fa7e420d4d500000000350000000000000051000000010000000000000000000000801a0600000000000000000000000000014000000000000000303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300600000000000000000000000000000000";
        test_tx_matches_expected(&payment_tx, expected);
    }

    #[test]
    fn test_p2pkh_tx_fees() {
        let tokens = TokenAmount(400000);
        let fees = TokenAmount(1000);
        let (tx_ins, key_material) = test_construct_valid_inputs();

        let payment_tx = transaction_utils::construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]),
                asset: Asset::Token(tokens),
            },
            Some(ReceiverInfo {
                address: hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]),
                asset: Asset::Token(fees),
            }),
            0,
            &key_material,
        );

        assert_eq!(Asset::Token(tokens), payment_tx.outputs[0].value);
        assert_eq!(Asset::Token(fees), payment_tx.fees[0].value);

        let tx_ins_spent = AssetValues::new(tokens + fees, BTreeMap::new());
        assert!(script_utils::tx_outs_are_valid(
            &payment_tx.outputs,
            &payment_tx.fees,
            tx_ins_spent,
        ));

        let expected = "01000000000000000120000000000000003030303030303030303030303030303030303030303030303030303030303030000000000800000000000000040000002000000000000000b240449307b3f9df0bc8a044fdc7f7e73690d9f28b4cf2b9b0ea8d4b683c9f3b01000000e36e2eec1a039c3c5c5df5df16bbad369d7b534e101b986a374cfe52f8a8622fb0e58ec38f9bb890285385c6a719d41eb128f4661f9aeb21ccce85267f1c2e04020000002a698271b680fd389ca2dc4823a8084065b2554caf0753b5ddc57a750564b1d40000000023000000000000005000000004000000200000000000000041063307a3fd68f3b03839c2889cd7ad0ae06259cad1be96ea4d8fa7e420d4d500000000350000000000000051000000010000000000000000000000801a0600000000000000000000000000014000000000000000303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300600000000000000010000000000000000000000e80300000000000000000000000000000140000000000000003030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303000";
        test_tx_matches_expected(&payment_tx, expected);
    }

    #[test]
    fn test_item_onspend() {
        let (tx_ins, key_material) = test_construct_valid_inputs();

        let drs_tx_hash = "item_tx_hash".to_string();
        let item_asset_valid = ItemAsset::new(1000, Some(drs_tx_hash.clone()), None);

        let payment_tx_valid = transaction_utils::construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]),
                asset: Asset::Item(item_asset_valid),
            },
            None,
            0,
            &key_material,
        );

        let tx_ins_spent = AssetValues::new(
            TokenAmount(0),
            BTreeMap::from([(drs_tx_hash, 1000)]));
        assert!(script_utils::tx_outs_are_valid(
            &payment_tx_valid.outputs,
            &payment_tx_valid.fees,
            tx_ins_spent,
        ));

        let expect = "01000000000000000120000000000000003030303030303030303030303030303030303030303030303030303030303030000000000800000000000000040000002000000000000000df5c06ca1043a15e1902a7b6894fcf7edbccc26d5f8ebe2f16038ae27c13454601000000d0eb36949fa7111a30e1c0724fb77adc7cce80898b2ce0de3093d380a009d742b89d14884f37313121973f5886f0da1b544e7f0035d9c45fe783e31372c4a107020000002a698271b680fd389ca2dc4823a8084065b2554caf0753b5ddc57a750564b1d40000000023000000000000005000000004000000200000000000000041063307a3fd68f3b03839c2889cd7ad0ae06259cad1be96ea4d8fa7e420d4d500000000350000000000000051000000010000000000000001000000e803000000000000010c000000000000006974656d5f74785f68617368000000000000000000014000000000000000303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300600000000000000000000000000000000";
        test_tx_matches_expected(&payment_tx_valid, expect);
    }

    #[test]
    fn test_item_onspend_with_fees() {
        let fees = TokenAmount(1000);
        let (tx_ins, key_material) = test_construct_valid_inputs();

        let drs_tx_hash = "item_tx_hash".to_string();
        let item_asset_valid = ItemAsset::new(1000, Some(drs_tx_hash.clone()), None);

        let payment_tx_valid = transaction_utils::construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]),
                asset: Asset::Item(item_asset_valid),
            },
            Some(ReceiverInfo {
                address: hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]),
                asset: Asset::Token(fees),
            }),
            0,
            &key_material,
        );

        let tx_ins_spent = AssetValues::new(
            fees,
            BTreeMap::from([(drs_tx_hash, 1000)]));
        assert!(script_utils::tx_outs_are_valid(
            &payment_tx_valid.outputs,
            &payment_tx_valid.fees,
            tx_ins_spent,
        ));

        let expect = "01000000000000000120000000000000003030303030303030303030303030303030303030303030303030303030303030000000000800000000000000040000002000000000000000df5c06ca1043a15e1902a7b6894fcf7edbccc26d5f8ebe2f16038ae27c13454601000000d0eb36949fa7111a30e1c0724fb77adc7cce80898b2ce0de3093d380a009d742b89d14884f37313121973f5886f0da1b544e7f0035d9c45fe783e31372c4a107020000002a698271b680fd389ca2dc4823a8084065b2554caf0753b5ddc57a750564b1d40000000023000000000000005000000004000000200000000000000041063307a3fd68f3b03839c2889cd7ad0ae06259cad1be96ea4d8fa7e420d4d500000000350000000000000051000000010000000000000001000000e803000000000000010c000000000000006974656d5f74785f68617368000000000000000000014000000000000000303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300600000000000000010000000000000000000000e80300000000000000000000000000000140000000000000003030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303000";
        test_tx_matches_expected(&payment_tx_valid, expect);
    }

    #[test]
    // Creates a valid UTXO set
    fn test_construct_valid_utxo_set() {
        let (pk, sk) = sign_ed25519::gen_test_keypair(0);

        let t_hash_1 = hex::encode(&[0u8; TX_HASH_LENGTH / 2]);

        let prev_out = OutPoint::new(hex::encode(t_hash_1), 0);
        let mut key_material = BTreeMap::new();
        key_material.insert(prev_out.clone(), (pk, sk.clone()));


        let tx_1 = TxConstructor {
            previous_out: OutPoint::new(hex::encode(&[0u8; TX_HASH_LENGTH / 2]), 0), //TODO
            signatures: vec![],
            pub_keys: vec![pk],
        };

        let token_amount = TokenAmount(400000);
        let tx_ins_1 = transaction_utils::construct_payment_tx_ins(vec![tx_1]);
        let payment_tx_1 = transaction_utils::construct_payment_tx(
            tx_ins_1,
            ReceiverInfo {
                address: hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]),
                asset: Asset::Token(token_amount),
            },
            None,
            0,
            &key_material,
        );
        let tx_1_hash = transaction_utils::construct_tx_hash(&payment_tx_1);
        let tx_1_out_p = OutPoint::new(tx_1_hash.clone(), 0);
        key_material.insert(tx_1_out_p.clone(), (pk, sk));

        let expected = "01000000000000000120000000000000003030303030303030303030303030303030303030303030303030303030303030000000000000000000000000010000000000000000000000801a0600000000000000000000000000014000000000000000303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300600000000000000000000000000000000";
        test_tx_matches_expected(&payment_tx_1, expected);

        // Second tx referencing first
        let tx_2 = TxConstructor {
            previous_out: tx_1_out_p.clone(),
            signatures: vec![],
            pub_keys: vec![pk],
        };
        let tx_ins_2 = transaction_utils::construct_payment_tx_ins(vec![tx_2]);
        let tx_outs = vec![TxOut::new_token_amount(
            hex::encode(&[1u8; STANDARD_ADDRESS_LENGTH_BYTES]),
            token_amount,
            None,
        )];
        let payment_tx_2 = transaction_utils::construct_tx_core(tx_ins_2, tx_outs, None);

        let tx_2_hash = transaction_utils::construct_tx_hash(&payment_tx_2);
        let tx_2_out_p = OutPoint::new(tx_2_hash, 0);

        let expected = "01000000000000000120000000000000006735343034336135656138323332333265653664313438663232363761666233000000000000000000000000010000000000000000000000801a0600000000000000000000000000014000000000000000303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130313031303130310600000000000000000000000000000000";
        test_tx_matches_expected(&payment_tx_2, expected);

        // BTreemap
        let mut btree = BTreeMap::new();
        btree.insert(tx_1_out_p, payment_tx_1);
        btree.insert(tx_2_out_p.clone(), payment_tx_2);

        transaction_utils::update_utxo_set(&mut btree);

        // Check that only one entry remains
        assert_eq!(btree.len(), 1);
        assert_ne!(btree.get(&tx_2_out_p), None);
    }
}