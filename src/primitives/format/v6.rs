use std::convert::TryInto;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::crypto::{sha3_256, sign_ed25519};
use crate::crypto::sign_ed25519::{PublicKey, Signature};
use crate::primitives::address::{AnyAddress, ParseAddressError};
use crate::primitives::asset::{Asset, ItemAsset, TokenAmount};
use crate::primitives::druid::{DdeValues, DruidExpectation};
use crate::primitives::transaction::*;
use crate::script::lang::{Script, ScriptBuilder};
use crate::script::{OpCodes, ScriptError};
use crate::utils::{script_utils, transaction_utils};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6PublicKey(
        #[serde(serialize_with = "<[_]>::serialize")]
        #[serde(deserialize_with = "v6_deserialize_slice")]
        [u8; 32]
);

impl From<&PublicKey> for V6PublicKey {
    fn from(value: &PublicKey) -> Self {
        Self(value.as_ref().try_into().unwrap())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct V6Signature(
        #[serde(serialize_with = "<[_]>::serialize")]
        #[serde(deserialize_with = "v6_deserialize_slice")]
        [u8; 64]
);

impl From<&Signature> for V6Signature {
    fn from(value: &Signature) -> Self {
        Self(value.as_ref().try_into().unwrap())
    }
}

fn v6_deserialize_slice<'de, D: serde::Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let value: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
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
    script_signature: V6Script,
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
    version: u64,
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
    participants: u64,
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

make_error_type!(pub enum FromV6Error {
    BadVersion(version: u64); "not a v6 transaction: {version}",
    DataRemaining(remaining: usize);
        "{remaining} bytes left over after v6 transaction deserialization",

    BadOpcode(name: &'static str); "script contained unsupported opcode \"{name}\"",
    NotHexBytes(bytes: String, cause: hex::FromHexError);
        "script contained invalid hex bytes: \"{bytes}\": {cause}"; cause,

    BadTxHash(cause: TxHashError);
        "transaction contained invalid transaction hash: {cause}"; cause,
    BadOutPointIndex(index: i32); "negative outpoint index: {index}",

    BadAddress(script_public_key: String, cause: ParseAddressError);
        "transaction contained invalid script_public_key \"{script_public_key}\": {cause}"; cause,
    BadDruidFromAddress(cause: ParseAddressError);
        "transaction contained DRUID expectation with invalid from address: {cause}"; cause,
    BadDruidToAddress(cause: ParseAddressError);
        "transaction contained DRUID expectation with invalid to address: {cause}"; cause,
    BadItemGenesisHash(cause: TxHashError);
        "create transaction contained invalid genesis_hash: {cause}"; cause,

    BadScriptPattern(script: String); "unknown v6 script format: {script}",
    HasPreviousOut(pattern_type: &'static str);
        "{pattern_type} transaction input must not have a previous_out",
    MissingPreviousOut(pattern_type: &'static str);
        "{pattern_type} transaction input must have a previous_out",
    BadP2PKHHash; "P2PKH TxIn public key hash doesn't match public key",
    BadP2PKHCheckData; "P2PKH TxIn check_data isn't valid",
    BadP2PKHSignature; "P2PKH TxIn signature isn't valid",

    Deserialize(cause: bincode::error::DecodeError);
        "failed to deserialize v6 transaction: {cause}"; cause,
});

fn upgrade_v6_asset(old: &V6Asset) -> Result<Asset, FromV6Error> {
    match old {
        V6Asset::Token(V6TokenAmount(amount)) => Ok(Asset::Token(TokenAmount(*amount))),
        V6Asset::Item(V6ItemAsset { amount, genesis_hash, metadata, }) =>
            Ok(Asset::Item(ItemAsset {
                amount: *amount,
                genesis_hash: genesis_hash.as_ref()
                    .map(|hash| hash.parse().map_err(FromV6Error::BadItemGenesisHash))
                    .transpose()?,
                metadata: metadata.clone(),
            })),
    }
}

fn upgrade_v6_script(old: &V6Script) -> Result<Script, FromV6Error> {
    let mut builder = ScriptBuilder::new();
    for entry in &old.stack {
        match entry {
            V6StackEntry::Op(op) => match op {
                V6OpCodes::OP_0 => builder.push_int(0),
                V6OpCodes::OP_1 => builder.push_int(1),
                V6OpCodes::OP_2 => builder.push_int(2),
                V6OpCodes::OP_3 => builder.push_int(3),
                V6OpCodes::OP_4 => builder.push_int(4),
                V6OpCodes::OP_5 => builder.push_int(5),
                V6OpCodes::OP_6 => builder.push_int(6),
                V6OpCodes::OP_7 => builder.push_int(7),
                V6OpCodes::OP_8 => builder.push_int(8),
                V6OpCodes::OP_9 => builder.push_int(9),
                V6OpCodes::OP_10 => builder.push_int(10),
                V6OpCodes::OP_11 => builder.push_int(11),
                V6OpCodes::OP_12 => builder.push_int(12),
                V6OpCodes::OP_13 => builder.push_int(13),
                V6OpCodes::OP_14 => builder.push_int(14),
                V6OpCodes::OP_15 => builder.push_int(15),
                V6OpCodes::OP_16 => builder.push_int(16),
                V6OpCodes::OP_NOP => builder.push_op(OpCodes::OP_NOP),
                V6OpCodes::OP_IF => builder.push_op(OpCodes::OP_IF),
                V6OpCodes::OP_NOTIF => builder.push_op(OpCodes::OP_NOTIF),
                V6OpCodes::OP_ELSE => builder.push_op(OpCodes::OP_ELSE),
                V6OpCodes::OP_ENDIF => builder.push_op(OpCodes::OP_ENDIF),
                V6OpCodes::OP_VERIFY => builder.push_op(OpCodes::OP_VERIFY),
                V6OpCodes::OP_BURN => builder.push_op(OpCodes::OP_BURN),
                V6OpCodes::OP_TOALTSTACK => builder.push_op(OpCodes::OP_TOALTSTACK),
                V6OpCodes::OP_FROMALTSTACK => builder.push_op(OpCodes::OP_FROMALTSTACK),
                V6OpCodes::OP_2DROP => builder.push_op(OpCodes::OP_2DROP),
                V6OpCodes::OP_2DUP => builder.push_op(OpCodes::OP_2DUP),
                V6OpCodes::OP_3DUP => builder.push_op(OpCodes::OP_3DUP),
                V6OpCodes::OP_2OVER => builder.push_op(OpCodes::OP_2OVER),
                V6OpCodes::OP_2ROT => builder.push_op(OpCodes::OP_2ROT),
                V6OpCodes::OP_2SWAP => builder.push_op(OpCodes::OP_2SWAP),
                V6OpCodes::OP_IFDUP => builder.push_op(OpCodes::OP_IFDUP),
                V6OpCodes::OP_DEPTH => builder.push_op(OpCodes::OP_DEPTH),
                V6OpCodes::OP_DROP => builder.push_op(OpCodes::OP_DROP),
                V6OpCodes::OP_DUP => builder.push_op(OpCodes::OP_DUP),
                V6OpCodes::OP_NIP => builder.push_op(OpCodes::OP_NIP),
                V6OpCodes::OP_OVER => builder.push_op(OpCodes::OP_OVER),
                V6OpCodes::OP_PICK => builder.push_op(OpCodes::OP_PICK),
                V6OpCodes::OP_ROLL => builder.push_op(OpCodes::OP_ROLL),
                V6OpCodes::OP_ROT => builder.push_op(OpCodes::OP_ROT),
                V6OpCodes::OP_SWAP => builder.push_op(OpCodes::OP_SWAP),
                V6OpCodes::OP_TUCK => builder.push_op(OpCodes::OP_TUCK),
                V6OpCodes::OP_CAT => builder.push_op(OpCodes::OP_CAT),
                V6OpCodes::OP_SUBSTR => builder.push_op(OpCodes::OP_SUBSTR),
                V6OpCodes::OP_LEFT => builder.push_op(OpCodes::OP_LEFT),
                V6OpCodes::OP_RIGHT => builder.push_op(OpCodes::OP_RIGHT),
                V6OpCodes::OP_SIZE => builder.push_op(OpCodes::OP_SIZE),
                V6OpCodes::OP_INVERT => builder.push_op(OpCodes::OP_INVERT),
                V6OpCodes::OP_AND => builder.push_op(OpCodes::OP_AND),
                V6OpCodes::OP_OR => builder.push_op(OpCodes::OP_OR),
                V6OpCodes::OP_XOR => builder.push_op(OpCodes::OP_XOR),
                V6OpCodes::OP_EQUAL => builder.push_op(OpCodes::OP_EQUAL),
                V6OpCodes::OP_EQUALVERIFY => builder.push_op(OpCodes::OP_EQUALVERIFY),
                V6OpCodes::OP_1ADD => builder.push_op(OpCodes::OP_1ADD),
                V6OpCodes::OP_1SUB => builder.push_op(OpCodes::OP_1SUB),
                V6OpCodes::OP_2MUL => builder.push_op(OpCodes::OP_2MUL),
                V6OpCodes::OP_2DIV => builder.push_op(OpCodes::OP_2DIV),
                V6OpCodes::OP_NOT => builder.push_op(OpCodes::OP_NOT),
                V6OpCodes::OP_0NOTEQUAL => builder.push_op(OpCodes::OP_0NOTEQUAL),
                V6OpCodes::OP_ADD => builder.push_op(OpCodes::OP_ADD),
                V6OpCodes::OP_SUB => builder.push_op(OpCodes::OP_SUB),
                V6OpCodes::OP_MUL => builder.push_op(OpCodes::OP_MUL),
                V6OpCodes::OP_DIV => builder.push_op(OpCodes::OP_DIV),
                V6OpCodes::OP_MOD => builder.push_op(OpCodes::OP_MOD),
                V6OpCodes::OP_LSHIFT => builder.push_op(OpCodes::OP_LSHIFT),
                V6OpCodes::OP_RSHIFT => builder.push_op(OpCodes::OP_RSHIFT),
                V6OpCodes::OP_BOOLAND => builder.push_op(OpCodes::OP_BOOLAND),
                V6OpCodes::OP_BOOLOR => builder.push_op(OpCodes::OP_BOOLOR),
                V6OpCodes::OP_NUMEQUAL => builder.push_op(OpCodes::OP_NUMEQUAL),
                V6OpCodes::OP_NUMEQUALVERIFY => builder.push_op(OpCodes::OP_NUMEQUALVERIFY),
                V6OpCodes::OP_NUMNOTEQUAL => builder.push_op(OpCodes::OP_NUMNOTEQUAL),
                V6OpCodes::OP_LESSTHAN => builder.push_op(OpCodes::OP_LESSTHAN),
                V6OpCodes::OP_GREATERTHAN => builder.push_op(OpCodes::OP_GREATERTHAN),
                V6OpCodes::OP_LESSTHANOREQUAL => builder.push_op(OpCodes::OP_LESSTHANOREQUAL),
                V6OpCodes::OP_GREATERTHANOREQUAL => builder.push_op(OpCodes::OP_GREATERTHANOREQUAL),
                V6OpCodes::OP_MIN => builder.push_op(OpCodes::OP_MIN),
                V6OpCodes::OP_MAX => builder.push_op(OpCodes::OP_MAX),
                V6OpCodes::OP_WITHIN => builder.push_op(OpCodes::OP_WITHIN),
                V6OpCodes::OP_SHA3 => builder.push_op(OpCodes::OP_SHA3),
                V6OpCodes::OP_HASH256 => builder.push_op(OpCodes::OP_HASH256),
                V6OpCodes::OP_HASH256_V0 => return Err(FromV6Error::BadOpcode("OP_HASH256_V0")),
                V6OpCodes::OP_HASH256_TEMP => return Err(FromV6Error::BadOpcode("OP_HASH256_TEMP")),
                V6OpCodes::OP_CHECKSIG => builder.push_op(OpCodes::OP_CHECKSIG),
                V6OpCodes::OP_CHECKSIGVERIFY => builder.push_op(OpCodes::OP_CHECKSIGVERIFY),
                V6OpCodes::OP_CHECKMULTISIG => builder.push_op(OpCodes::OP_CHECKMULTISIG),
                V6OpCodes::OP_CHECKMULTISIGVERIFY => builder.push_op(OpCodes::OP_CHECKMULTISIGVERIFY),
                V6OpCodes::OP_CREATE => builder.push_op(OpCodes::OP_CREATE),
                V6OpCodes::OP_NOP1 => builder.push_op(OpCodes::OP_NOP1),
                V6OpCodes::OP_NOP2 => builder.push_op(OpCodes::OP_NOP2),
                V6OpCodes::OP_NOP3 => builder.push_op(OpCodes::OP_NOP3),
                V6OpCodes::OP_NOP4 => builder.push_op(OpCodes::OP_NOP4),
                V6OpCodes::OP_NOP5 => builder.push_op(OpCodes::OP_NOP5),
                V6OpCodes::OP_NOP6 => builder.push_op(OpCodes::OP_NOP6),
                V6OpCodes::OP_NOP7 => builder.push_op(OpCodes::OP_NOP7),
                V6OpCodes::OP_NOP8 => builder.push_op(OpCodes::OP_NOP8),
                V6OpCodes::OP_NOP9 => builder.push_op(OpCodes::OP_NOP9),
                V6OpCodes::OP_NOP10 => builder.push_op(OpCodes::OP_NOP10),
            },
            V6StackEntry::Signature(signature) => builder.push_data(&signature.0),
            V6StackEntry::PubKey(pubkey) => builder.push_data(&pubkey.0),
            V6StackEntry::Num(num) => builder.push_int(*num),
            V6StackEntry::Bytes(bytes) => builder.push_data(&hex::decode(bytes)
                    .map_err(|err| FromV6Error::NotHexBytes(bytes.clone(), err))?),
        }
    }
    Ok(builder.finish())
}

fn upgrade_v6_outpoint(old: &V6OutPoint) -> Result<OutPoint, FromV6Error> {
    Ok(OutPoint {
        t_hash: old.t_hash.parse().map_err(FromV6Error::BadTxHash)?,
        n: old.n.try_into().map_err(|_| FromV6Error::BadOutPointIndex(old.n))?,
    })
}

fn upgrade_v6_txin(old: &V6TxIn, upgraded_txouts: &[TxOut]) -> Result<TxIn, FromV6Error> {
    let previous_out = old.previous_out.as_ref()
        .map(upgrade_v6_outpoint)
        .transpose()?;

    //match &old.script_signature.stack.as_slice()[..] {
    match &old.script_signature.stack.as_slice() {
        [ // Coinbase
        V6StackEntry::Num(block_number)
        ] => match previous_out {
            None => Ok(TxIn::Coinbase(CoinbaseTxIn {
                block_number: *block_number,
            })),
            Some(_) => Err(FromV6Error::HasPreviousOut("coinbase")),
        },

        [ // Create
        V6StackEntry::Op(V6OpCodes::OP_CREATE),
        V6StackEntry::Num(block_number),
        V6StackEntry::Op(V6OpCodes::OP_DROP),
        V6StackEntry::Bytes(b),
        V6StackEntry::Signature(signature),
        V6StackEntry::PubKey(public_key),
        V6StackEntry::Op(V6OpCodes::OP_CHECKSIG),
        ] => match previous_out {
            None => Ok(TxIn::Create(CreateTxIn {
                block_number: *block_number,
                asset_hash: hex::decode(b).map_err(|err| FromV6Error::NotHexBytes(b.clone(), err))?,
                public_key: PublicKey::from_slice(&public_key.0).unwrap(),
                signature: Signature::from_slice(&signature.0).unwrap(),
            })),
            Some(_) => Err(FromV6Error::HasPreviousOut("create")),
        },

        [ // P2PKH
        V6StackEntry::Bytes(check_data),
        V6StackEntry::Signature(signature),
        V6StackEntry::PubKey(public_key),
        V6StackEntry::Op(V6OpCodes::OP_DUP),
        V6StackEntry::Op(V6OpCodes::OP_HASH256),
        V6StackEntry::Bytes(public_key_hash),
        V6StackEntry::Op(V6OpCodes::OP_EQUALVERIFY),
        V6StackEntry::Op(V6OpCodes::OP_CHECKSIG),
        ] => match previous_out {
            Some(previous_out) => {
                // Verify that the public key hash is correct
                let expected_hash = hex::encode(sha3_256::digest(&public_key.0));
                if expected_hash != *public_key_hash {
                    return Err(FromV6Error::BadP2PKHHash);
                }

                // Verify that the check_data is valid
                let expected_check_data_1 = transaction_utils::construct_tx_in_signable_hash(
                    &previous_out);
                let expected_check_data_2 = transaction_utils::construct_tx_in_out_signable_hash(
                    &previous_out, upgraded_txouts);
                if expected_check_data_1 != *check_data && expected_check_data_2 != *check_data {
                    return Err(FromV6Error::BadP2PKHCheckData);
                }

                // Verify that the signature is valid
                let public_key = PublicKey::from_slice(&public_key.0).unwrap();
                let signature = Signature::from_slice(&signature.0).unwrap();
                if !sign_ed25519::verify_detached(&signature, check_data.as_bytes(), &public_key) {
                    return Err(FromV6Error::BadP2PKHSignature);
                }

                Ok(TxIn::P2PKH(P2PKHTxIn {
                    previous_out,
                    public_key,
                    signature,
                }))
            },
            None => Err(FromV6Error::HasPreviousOut("p2pkh")),
        },

        _ => Err(FromV6Error::BadScriptPattern(format!("{:?}", old.script_signature))),
    }
}

fn upgrade_v6_txout(old: &V6TxOut) -> Result<TxOut, FromV6Error> {
    Ok(TxOut {
        value: upgrade_v6_asset(&old.value)?,
        locktime: old.locktime,
        script_public_key: match &old.script_public_key {
            // If script_public_key is unset, the output is effectively a burn output
            None => AnyAddress::Burn,
            Some(text_address) => match AnyAddress::from_str(text_address) {
                Ok(address) => address,
                Err(err) => return Err(FromV6Error::BadAddress(text_address.clone(), err)),
            },
        },
    })
}

fn upgrade_v6_druidexpectation(old: &V6DruidExpectation) -> Result<DruidExpectation, FromV6Error> {
    Ok(DruidExpectation {
        from: old.from.parse().map_err(FromV6Error::BadDruidFromAddress)?,
        to: old.to.parse().map_err(FromV6Error::BadDruidToAddress)?,
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
        genesis_hash: old.genesis_hash.as_ref()
                    .map(|hash| hash.parse().map_err(FromV6Error::BadItemGenesisHash))
                    .transpose()?,
    })
}

fn upgrade_v6_tx(old: &V6Transaction) -> Result<Transaction, FromV6Error> {
    if old.version != 6 {
        return Err(FromV6Error::BadVersion(old.version));
    }

    let outputs = old.outputs.iter().map(upgrade_v6_txout).collect::<Result<Vec<_>, _>>()?;
    let fees = old.fees.iter().map(upgrade_v6_txout).collect::<Result<Vec<_>, _>>()?;
    let druid_info = old.druid_info.as_ref().map(upgrade_v6_ddevalues).transpose()?;
    let inputs = old.inputs.iter()
        .map(|old_txin| upgrade_v6_txin(old_txin, &outputs))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Transaction {
        version: TxVersion::V6,
        inputs,
        outputs,
        fees,
        druid_info,
    })
}

/// Tries to deserialize a v6 transaction into the new object representation.
///
/// ### Arguments
///
/// * `bytes`  - a slice containing the serialized v6 transaction
pub fn deserialize(bytes: &[u8]) -> Result<Transaction, FromV6Error> {
    let (tx, read_bytes) =
        bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
            .map_err(FromV6Error::Deserialize)?;

    if read_bytes == bytes.len() {
        upgrade_v6_tx(&tx)
    } else {
        Err(FromV6Error::DataRemaining(bytes.len() - read_bytes))
    }
}

make_error_type!(pub enum ToV6Error {
    BadVersion(version: TxVersion); "not a v6 transaction: {version}",

    BadOpcode(name: &'static str); "script contained unsupported opcode \"{name}\"",
    NotHexBytes(bytes: String, cause: hex::FromHexError);
        "script contained invalid hex bytes: \"{bytes}\": {cause}"; cause,
    CantDecodeScript(cause: ScriptError); "failed to decode script: {cause}"; cause,
    BadScript; "script doesn't match any known v6 patterns",

    BadAddress(address: AnyAddress);
        "{} address \"{address}\" cannot be converted to v6" (address.sort()),

    BadOutPointIndex(index: u32); "outpoint index too high: {index}",
    BadP2PKHSignature; "P2PKH TxIn signature doesn't match any known pattern",

    Serialize(cause: bincode::error::EncodeError);
        "failed to serialize v6 transaction: {cause}"; cause,
});

fn downgrade_v6_asset(old: &Asset) -> Result<V6Asset, ToV6Error> {
    match old {
        Asset::Token(TokenAmount(amount)) => Ok(V6Asset::Token(V6TokenAmount(*amount))),
        Asset::Item(ItemAsset { amount, genesis_hash, metadata, }) =>
            Ok(V6Asset::Item(V6ItemAsset {
                amount: *amount,
                genesis_hash: genesis_hash.as_ref().map(TxHash::to_string),
                metadata: metadata.clone(),
            })),
    }
}

fn downgrade_v6_outpoint(old: &OutPoint) -> Result<V6OutPoint, ToV6Error> {
    Ok(V6OutPoint {
        t_hash: old.t_hash.to_string(),
        n: old.n.try_into().map_err(|_| ToV6Error::BadOutPointIndex(old.n))?,
    })
}

fn downgrade_v6_txin(old: &TxIn, new_txouts: &[TxOut]) -> Result<V6TxIn, ToV6Error> {
    Ok(match old {
        TxIn::Coinbase(coinbase) => V6TxIn {
            previous_out: None,
            script_signature: V6Script {
                stack: vec![
                    V6StackEntry::Num(coinbase.block_number),
                ]
            },
        },
        TxIn::Create(create) => V6TxIn {
            previous_out: None,
            script_signature: V6Script {
                stack: vec![
                    V6StackEntry::Op(V6OpCodes::OP_CREATE),
                    V6StackEntry::Num(create.block_number),
                    V6StackEntry::Op(V6OpCodes::OP_DROP),
                    V6StackEntry::Bytes(hex::encode(&create.asset_hash)),
                    V6StackEntry::Signature((&create.signature).into()),
                    V6StackEntry::PubKey((&create.public_key).into()),
                    V6StackEntry::Op(V6OpCodes::OP_CHECKSIG),
                ]
            },
        },
        TxIn::P2PKH(p2pkh) => V6TxIn {
            previous_out: Some(downgrade_v6_outpoint(&p2pkh.previous_out)?),
            script_signature: {
                let check_data = find_v6_p2pkh_check_data(p2pkh, new_txouts)
                    .ok_or(ToV6Error::BadP2PKHSignature)?;

                V6Script {
                    stack: vec![
                        V6StackEntry::Bytes(check_data),
                        V6StackEntry::Signature((&p2pkh.signature).into()),
                        V6StackEntry::PubKey((&p2pkh.public_key).into()),
                        V6StackEntry::Op(V6OpCodes::OP_DUP),
                        V6StackEntry::Op(V6OpCodes::OP_HASH256),
                        V6StackEntry::Bytes(hex::encode(sha3_256::digest(p2pkh.public_key.as_ref()))),
                        V6StackEntry::Op(V6OpCodes::OP_EQUALVERIFY),
                        V6StackEntry::Op(V6OpCodes::OP_CHECKSIG),
                    ]
                }
            },
        },
    })
}

fn downgrade_v6_txout(old: &TxOut) -> Result<V6TxOut, ToV6Error> {
    Ok(V6TxOut {
        value: downgrade_v6_asset(&old.value)?,
        locktime: old.locktime,
        script_public_key: match &old.script_public_key {
            AnyAddress::P2PKH(p2pkh) => Some(p2pkh.to_string()),
            AnyAddress::Burn => None,
        },
    })
}

fn downgrade_v6_druidexpectation(old: &DruidExpectation) -> Result<V6DruidExpectation, ToV6Error> {
    Ok(V6DruidExpectation {
        from: old.from.to_string(),
        to: old.to.to_string(),
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
        genesis_hash: old.genesis_hash.as_ref().map(TxHash::to_string),
    })
}

fn downgrade_v6_tx(old: &Transaction) -> Result<V6Transaction, ToV6Error> {
    if old.version != TxVersion::V6 {
        return Err(ToV6Error::BadVersion(old.version));
    }
    
    Ok(V6Transaction {
        version: 6,
        inputs: old.inputs.iter()
            .map(|tx_in| downgrade_v6_txin(tx_in, &old.outputs))
            .collect::<Result<Vec<_>, _>>()?,
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
    bincode::serde::encode_to_vec(&downgrade_v6_tx(tx)?, bincode::config::legacy())
        .map_err(ToV6Error::Serialize)
}

/// Given a P2PKH `TxIn`, determine whether it signed `construct_tx_in_signable_hash` or
/// `construct_tx_in_out_signable_hash`.
///
/// ### Arguments
///
/// * `tx_in`   - A P2PKH transaction input from a v6 transaction in the new object representation
/// * `tx_outs` - All transaction outputs from the same v6 transaction in the new object
///               representation
pub fn find_v6_p2pkh_check_data(
    tx_in: &P2PKHTxIn,
    tx_outs: &[TxOut],
) -> Option<String> {
    // Figure out which signable_hash function was used to sign this transaction
    let expected_check_data_1 = transaction_utils::construct_tx_in_signable_hash(
        &tx_in.previous_out);
    let expected_check_data_2 = transaction_utils::construct_tx_in_out_signable_hash(
        &tx_in.previous_out, tx_outs);

    if sign_ed25519::verify_detached(
        &tx_in.signature, expected_check_data_1.as_bytes(), &tx_in.public_key) {
        Some(expected_check_data_1)
    } else if sign_ed25519::verify_detached(
        &tx_in.signature, expected_check_data_2.as_bytes(), &tx_in.public_key) {
        Some(expected_check_data_2)
    } else {
        None
    }
}

/*/// Checks if a transaction meets all the requirements for upgrading to version 7, otherwise
/// it panics.
///
/// Aside from artificial transactions created in test code, this should always pass.
pub fn validate_v7_preconditions(tx: &Transaction) {
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
    use std::str::from_utf8;
    use once_cell::sync::Lazy;
    use crate::constants::STANDARD_ADDRESS_LENGTH_BYTES;
    use crate::crypto::sign_ed25519;
    use crate::crypto::sign_ed25519::{PublicKey, SecretKey};
    use crate::primitives::address::P2PKHAddress;
    use crate::primitives::asset::{Asset, AssetValues, ItemAsset, TokenAmount};
    use crate::primitives::transaction::{OutPoint, Transaction, TxConstructor, TxIn};
    use crate::utils::{Placeholder, script_utils, transaction_utils};
    use crate::utils::transaction_utils::ReceiverInfo;

    fn test_construct_valid_inputs() -> (Vec<TxInConstructor<'static>>, BTreeMap<OutPoint, (PublicKey, SecretKey)>) {
        static KEYPAIR : Lazy<(PublicKey, SecretKey)> = Lazy::new(|| sign_ed25519::gen_test_keypair(0).unwrap());
        static PREV_OUT : Lazy<OutPoint> = Lazy::new(|| {
            let t_hash = "g48dda5bbe9171a6656206ec56c595c5";
            OutPoint::new_from_hash(t_hash.parse().unwrap(), 0)
        });

        let (pk, sk) = &*KEYPAIR;
        let prev_out = &*PREV_OUT;

        let key_material = BTreeMap::from([
            ( prev_out.clone(), (pk.clone(), sk.clone()) ),
        ]);

        let tx_ins = vec![TxInConstructor::P2PKH {
            previous_out: prev_out,
            public_key: pk,
            secret_key: sk,
        }];
        (tx_ins, key_material)
    }

    fn test_tx_matches_expected(tx: &Transaction, expected_hex: &str) {
        let v6_ser = super::serialize(tx).unwrap();
        let v6_hex = hex::encode(&v6_ser);
        assert_eq!(v6_hex, expected_hex);

        let expected_ser = hex::decode(expected_hex).unwrap();
        let expected = super::deserialize(&expected_ser).unwrap();
        assert_eq!(tx, &expected);
    }

    #[test]
    fn test_p2pkh_tx() {
        let tokens = TokenAmount(400000);
        let (tx_ins, key_material) = test_construct_valid_inputs();

        let payment_tx = transaction_utils::construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]).parse().unwrap(),
                asset: Asset::Token(tokens),
            },
            None,
            0,
            &key_material,
        );

        assert_eq!(Asset::Token(tokens), payment_tx.outputs[0].value);
        assert_eq!(
            payment_tx.outputs[0].script_public_key,
            AnyAddress::P2PKH(hex::encode(&[0u8; STANDARD_ADDRESS_LENGTH_BYTES]).parse().unwrap())
        );

        let tx_ins_spent = AssetValues::new(tokens, BTreeMap::new());
        assert!(script_utils::tx_outs_are_valid(
            &payment_tx.outputs,
            &payment_tx.fees,
            tx_ins_spent,
        ));

        let expected = "0100000000000000012000000000000000673438646461356262653931373161363635363230366563353663353935633500000000080000000000000004000000400000000000000031323830663236323866313731613033616334376366653762376363313164633238303331323930646530353561616634353664383764623234383762313731010000004000000000000000b5e781e1f1dc2f330136730490b2ba25fc2b6d76fb84c84ed15b5c78f1f5926b6d817c15a4ce7993ad9e3ec205b0c1e2f4334bc12badbd7a8af7b4ab2801fc030200000020000000000000004a423a99c7d946e88da185f8f400e41cee388a95ecedc8603136de50aea12182000000002300000000000000500000000400000040000000000000003039653138346234363365356538643465666161336666353130663138343231633765353066653432666534646137623534353332636132303666333339626200000000350000000000000053000000010000000000000000000000801a0600000000000000000000000000014000000000000000303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300600000000000000000000000000000000";
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
                address: P2PKHAddress::placeholder_indexed(4).wrap(),
                asset: Asset::Token(tokens),
            },
            Some(ReceiverInfo {
                address: P2PKHAddress::placeholder_indexed(5).wrap(),
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

        let expected = "0100000000000000012000000000000000673438646461356262653931373161363635363230366563353663353935633500000000080000000000000004000000400000000000000063653137663764316636373539643734326661363763343132343038363863633733393639383431336639313336393330623763383536366135336561663966010000004000000000000000ddb2e62a24f2004b1977afb82700a46121f6f0070c9ccaa24828c82c9806d39eb51921489f34c198861c8d19552324d9813a97e1c5de985db792e1df5914ed0a0200000020000000000000004a423a99c7d946e88da185f8f400e41cee388a95ecedc8603136de50aea12182000000002300000000000000500000000400000040000000000000003039653138346234363365356538643465666161336666353130663138343231633765353066653432666534646137623534353332636132303666333339626200000000350000000000000053000000010000000000000000000000801a0600000000000000000000000000014000000000000000393732653338613030616630323036393065313736663566613465653634613131653362643663626330303037633130666434626265326337356130313062640600000000000000010000000000000000000000e80300000000000000000000000000000140000000000000006261616365313962326639353533343334383539363638653037383231643236336562363166353131326264346335336535346436356530323964383838313600";
        test_tx_matches_expected(&payment_tx, expected);
    }

    #[test]
    fn test_item_onspend() {
        let (tx_ins, key_material) = test_construct_valid_inputs();

        let drs_tx_hash : TxHash = "gb875632ccf606eef2397124e6c2febf".parse().unwrap();
        let item_asset_valid = ItemAsset::new(1000, Some(drs_tx_hash.clone()), None);

        let payment_tx_valid = transaction_utils::construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: P2PKHAddress::placeholder_indexed(4).wrap(),
                asset: Asset::Item(item_asset_valid),
            },
            None,
            0,
            &key_material,
        );

        let tx_ins_spent = AssetValues::new(
            TokenAmount(0),
            BTreeMap::from([(drs_tx_hash.clone(), 1000)]));
        assert!(script_utils::tx_outs_are_valid(
            &payment_tx_valid.outputs,
            &payment_tx_valid.fees,
            tx_ins_spent,
        ));

        let expect = "0100000000000000012000000000000000673438646461356262653931373161363635363230366563353663353935633500000000080000000000000004000000400000000000000063343366656462666236366639363265613036323933313838373361326136616665613236356265613863396235336564393066353864616563646234396537010000004000000000000000c1f07613c895c429836635ab18231ff2df2852aadab0988e4edf5ddc95ad308cbeb8c89550e3abed5aca2f086d978195a52d3e8518272609cd75053fc71325010200000020000000000000004a423a99c7d946e88da185f8f400e41cee388a95ecedc8603136de50aea12182000000002300000000000000500000000400000040000000000000003039653138346234363365356538643465666161336666353130663138343231633765353066653432666534646137623534353332636132303666333339626200000000350000000000000053000000010000000000000001000000e8030000000000000120000000000000006762383735363332636366363036656566323339373132346536633266656266000000000000000000014000000000000000393732653338613030616630323036393065313736663566613465653634613131653362643663626330303037633130666434626265326337356130313062640600000000000000000000000000000000";
        test_tx_matches_expected(&payment_tx_valid, expect);
    }

    #[test]
    fn test_item_onspend_with_fees() {
        let fees = TokenAmount(1000);
        let (tx_ins, key_material) = test_construct_valid_inputs();

        let drs_tx_hash : TxHash = "gb875632ccf606eef2397124e6c2febf".parse().unwrap();
        let item_asset_valid = ItemAsset::new(1000, Some(drs_tx_hash.clone()), None);

        let payment_tx_valid = transaction_utils::construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: P2PKHAddress::placeholder_indexed(4).wrap(),
                asset: Asset::Item(item_asset_valid),
            },
            Some(ReceiverInfo {
                address: P2PKHAddress::placeholder_indexed(5).wrap(),
                asset: Asset::Token(fees),
            }),
            0,
            &key_material,
        );

        let tx_ins_spent = AssetValues::new(
            fees,
            BTreeMap::from([(drs_tx_hash.clone(), 1000)]));
        assert!(script_utils::tx_outs_are_valid(
            &payment_tx_valid.outputs,
            &payment_tx_valid.fees,
            tx_ins_spent,
        ));

        let expect = "0100000000000000012000000000000000673438646461356262653931373161363635363230366563353663353935633500000000080000000000000004000000400000000000000063343366656462666236366639363265613036323933313838373361326136616665613236356265613863396235336564393066353864616563646234396537010000004000000000000000c1f07613c895c429836635ab18231ff2df2852aadab0988e4edf5ddc95ad308cbeb8c89550e3abed5aca2f086d978195a52d3e8518272609cd75053fc71325010200000020000000000000004a423a99c7d946e88da185f8f400e41cee388a95ecedc8603136de50aea12182000000002300000000000000500000000400000040000000000000003039653138346234363365356538643465666161336666353130663138343231633765353066653432666534646137623534353332636132303666333339626200000000350000000000000053000000010000000000000001000000e8030000000000000120000000000000006762383735363332636366363036656566323339373132346536633266656266000000000000000000014000000000000000393732653338613030616630323036393065313736663566613465653634613131653362643663626330303037633130666434626265326337356130313062640600000000000000010000000000000000000000e80300000000000000000000000000000140000000000000006261616365313962326639353533343334383539363638653037383231643236336562363166353131326264346335336535346436356530323964383838313600";
        test_tx_matches_expected(&payment_tx_valid, expect);
    }

    #[test]
    // Creates a valid UTXO set
    fn test_construct_valid_utxo_set() {
        let (pk, sk) = sign_ed25519::gen_test_keypair(0).unwrap();

        let t_hash_1 = "g48dda5bbe9171a6656206ec56c595c5";
        let prev_out = OutPoint::new_from_hash(t_hash_1.parse().unwrap(), 0);
        let mut key_material = BTreeMap::new();
        key_material.insert(prev_out.clone(), (pk, sk.clone()));

        let token_amount = TokenAmount(400000);
        let tx_ins_1 = vec![TxInConstructor::P2PKH {
            previous_out: &prev_out,
            public_key: &pk,
            secret_key: &sk,
        }];
        let payment_tx_1 = transaction_utils::construct_payment_tx(
            tx_ins_1,
            ReceiverInfo {
                address: P2PKHAddress::placeholder_indexed(4).wrap(),
                asset: Asset::Token(token_amount),
            },
            None,
            0,
            &key_material,
        );
        let tx_1_hash = transaction_utils::construct_tx_hash(&payment_tx_1);
        let tx_1_out_p = OutPoint::new_from_hash(tx_1_hash.parse().unwrap(), 0);
        key_material.insert(tx_1_out_p.clone(), (pk, sk.clone()));

        let expected = "0100000000000000012000000000000000673438646461356262653931373161363635363230366563353663353935633500000000080000000000000004000000400000000000000063653137663764316636373539643734326661363763343132343038363863633733393639383431336639313336393330623763383536366135336561663966010000004000000000000000ddb2e62a24f2004b1977afb82700a46121f6f0070c9ccaa24828c82c9806d39eb51921489f34c198861c8d19552324d9813a97e1c5de985db792e1df5914ed0a0200000020000000000000004a423a99c7d946e88da185f8f400e41cee388a95ecedc8603136de50aea12182000000002300000000000000500000000400000040000000000000003039653138346234363365356538643465666161336666353130663138343231633765353066653432666534646137623534353332636132303666333339626200000000350000000000000053000000010000000000000000000000801a0600000000000000000000000000014000000000000000393732653338613030616630323036393065313736663566613465653634613131653362643663626330303037633130666434626265326337356130313062640600000000000000000000000000000000";
        test_tx_matches_expected(&payment_tx_1, expected);

        // Second tx referencing first
        let tx_ins_2 = vec![TxInConstructor::P2PKH {
            previous_out: &tx_1_out_p,
            public_key: &pk,
            secret_key: &sk,
        }];
        let payment_tx_2 = transaction_utils::construct_payment_tx(
            tx_ins_2,
            ReceiverInfo {
                address: P2PKHAddress::placeholder_indexed(5).wrap(),
                asset: Asset::Token(token_amount),
            },
            None,
            0,
            &key_material);

        let tx_2_hash = transaction_utils::construct_tx_hash(&payment_tx_2);
        let tx_2_out_p = OutPoint::new_from_hash(tx_2_hash.parse().unwrap(), 0);

        let expected = "0100000000000000012000000000000000673633396266633638366261613139333733633639636666646632656462303000000000080000000000000004000000400000000000000064343637336438303466646165393162353261343837623961353461323638343539653261326636363632353135613064343431393762623537396137666164010000004000000000000000b66606dda7348046ced913bff36080a1a112dd01e5605d6696e105fcc3544e966b955e12d219f444c510b5b87c1c251a57a5a6e27a73472212d40493fcde610a0200000020000000000000004a423a99c7d946e88da185f8f400e41cee388a95ecedc8603136de50aea12182000000002300000000000000500000000400000040000000000000003039653138346234363365356538643465666161336666353130663138343231633765353066653432666534646137623534353332636132303666333339626200000000350000000000000053000000010000000000000000000000801a0600000000000000000000000000014000000000000000626161636531396232663935353334333438353936363865303738323164323633656236316635313132626434633533653534643635653032396438383831360600000000000000000000000000000000";
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
