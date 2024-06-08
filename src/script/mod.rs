#![allow(unused)]
pub mod interface_ops;
pub mod lang;

use std::convert::TryInto;
use crate::crypto::sign_ed25519::{PublicKey, Signature};
use crate::constants::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::{Formatter, write, Write};
use bincode::{BorrowDecode, Decode, Encode, impl_borrow_decode};
use bincode::de::{BorrowDecoder, Decoder};
use bincode::de::read::BorrowReader;
use bincode::enc::Encoder;
use bincode::error::{AllowedEnumVariants, DecodeError, EncodeError};
use serde::de::Unexpected;
use crate::script::lang::Script;
use crate::utils::{FromName, ToName, ToOrdinal};
use crate::utils::serialize_utils::{bincode_borrow_decode_from_slice_standard, bincode_encode_to_write_standard};

/// Stack entry enum
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum StackEntry {
    Op(OpCodes),
    Signature(Signature),
    PubKey(PublicKey),
    // TODO: This should probably be u64, as usize doesn't have a consistent range on all platforms
    Num(usize),
    Bytes(Vec<u8>),
}

macro_rules! opcodes_enum {
    (
        <regular_opcodes> $($regular_id:ident = $regular_num:literal; $regular_desc:literal,)*
        <const_int_opcodes> $($const_int_id:ident($const_int_val:literal) = $const_int_num:literal,)*
        <variable_int_opcode> $var_int_id:ident = $var_int_num:literal,
        <fixed_data_opcodes> $($fixed_data_id:ident([u8; $fixed_data_len:literal]) = $fixed_data_num:literal,)*
        <variable_data_opcode> $var_data_id:ident(Vec<u8>) = $var_data_num:literal,
    ) => {
        // This dummy enum simply serves as a compile-time check that none of the opcode numbers are
        // used more than once.
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
            #[repr(u8)]
            enum AllOpCodes {
                $( $regular_id = $regular_num, )*
                $( $const_int_id = $const_int_num, )*
                $var_int_id = $var_int_num,
                $( $fixed_data_id = $fixed_data_num, )*
                $var_data_id = $var_data_num,
            }
        };

        make_ordinal_enum!(
            #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
            #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
            pub enum OpCodes {
                $( $regular_id = $regular_num, )*
            }
            all_variants=pub ALL_OPCODES);

        impl OpCodes {
            /// This opcode's string description
            pub fn desc(&self) -> &'static str {
                match self {
                    $( Self::$regular_id => $regular_desc, )*
                }
            }
        }

        impl Serialize for OpCodes {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                assert!(serializer.is_human_readable(), "serializer must be human-readable!");
                serializer.serialize_str(self.to_name())
            }
        }

        impl<'de> Deserialize<'de> for OpCodes {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                assert!(deserializer.is_human_readable(), "deserializer must be human-readable!");

                let name : &str = Deserialize::deserialize(deserializer)?;
                match name {
                    $( stringify!($regular_id) => Ok(Self::$regular_id), )*
                    _ => Err(<D::Error as serde::de::Error>::unknown_variant(name, <Self as FromName>::ALL_NAMES)),
                }
            }
        }

        /// A single entry in a script. Represents either an opcode to be executed, or constant
        /// data to be pushed on the stack.
        #[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
        pub enum ScriptEntry<'a> {
            Op(OpCodes),
            Int(u64),
            Data(&'a [u8]),
        }

        impl Encode for ScriptEntry<'_> {
            fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
                match self {
                    Self::Op(op) => Encode::encode(&(op.to_ordinal() as u8), encoder),
                    Self::Int(int) => match int {
                        $( $const_int_val => Encode::encode(&($const_int_num as u8), encoder), )*
                        _ => {
                            Encode::encode(&($var_int_num as u8), encoder)?;
                            Encode::encode(int, encoder)
                        }
                    },
                    Self::Data(data) => match data.len() {
                        $(
                            // If the data length is one of the known constants, encode it without
                            // a length prefix by using the corresponding fixed-length byte opcode
                            $fixed_data_len => {
                                Encode::encode(&($fixed_data_num as u8), encoder)?;
                                let data : &[u8; $fixed_data_len] = (*data).try_into().unwrap();
                                Encode::encode(data, encoder)
                            }
                        )*
                        // Otherwise, use a length prefix.
                        _ => {
                            Encode::encode(&($var_data_num as u8), encoder)?;
                            Encode::encode(data, encoder)
                        }
                    }
                }
            }
        }

        impl<'de> BorrowDecode<'de> for ScriptEntry<'de> {
            fn borrow_decode<D: BorrowDecoder<'de>>(decoder: &mut D) -> Result<Self, DecodeError> {
                let op : u8 = Decode::decode(decoder)?;
                match op {
                    $( $regular_num => Ok(Self::Op(OpCodes::$regular_id)), )*
                    $( $const_int_num => Ok(Self::Int($const_int_val)), )*
                    $var_int_num => <u64 as Decode>::decode(decoder).map(Self::Int),
                    $( $fixed_data_num => decoder.borrow_reader().take_bytes($fixed_data_len).map(Self::Data), )*
                    $var_data_num => {
                        let len : usize = Decode::decode(decoder)?;
                        decoder.borrow_reader().take_bytes(len).map(Self::Data)
                    }
                    _ => Err(DecodeError::UnexpectedVariant {
                        type_name: "ScriptEntry",
                        allowed: &AllowedEnumVariants::Allowed(&[
                            $( $regular_num, )*
                            $( $const_int_num, )*
                            $var_int_num,
                            $( $fixed_data_num, )*
                            $var_data_num,
                        ]),
                        found: op as u32,
                    })
                }
            }
        }
    };
}

/// Opcodes enum
opcodes_enum!(
    <regular_opcodes>
    // flow control
    OP_NOP = 0x20; "Does nothing",
    OP_IF = 0x21; "Checks if the top item on the stack is not ZERO and executes the next block of instructions",
    OP_NOTIF = 0x22; "Checks if the top item on the stack is ZERO and executes the next block of instructions",
    OP_ELSE = 0x23; "Executes the next block of instructions if the previous OP_IF or OP_NOTIF was not executed",
    OP_ENDIF = 0x24; "Ends an OP_IF or OP_NOTIF block",
    OP_VERIFY = 0x25; "Removes the top item from the stack and ends execution with an error if it is ZERO",
    OP_BURN = 0x26; "Ends execution with an error",
    // stack
    OP_TOALTSTACK = 0x30; "Moves the top item from the main stack to the top of the alt stack",
    OP_FROMALTSTACK = 0x31; "Moves the top item from the alt stack to the top of the main stack",
    OP_2DROP = 0x32; "Removes the top two items from the stack",
    OP_2DUP = 0x33; "Duplicates the top two items on the stack",
    OP_3DUP = 0x34; "Duplicates the top three items on the stack",
    OP_2OVER = 0x35; "Copies the second-to-top pair of items to the top of the stack",
    OP_2ROT = 0x36; "Moves the third-to-top pair of items to the top of the stack",
    OP_2SWAP = 0x37; "Swaps the top two pairs of items on the stack",
    OP_IFDUP = 0x38; "Duplicates the top item on the stack if it is not ZERO",
    OP_DEPTH = 0x39; "Pushes the stack size onto the stack",
    OP_DROP = 0x3a; "Removes the top item from the stack",
    OP_DUP = 0x3b; "Duplicates the top item on the stack",
    OP_NIP = 0x3c; "Removes the second-to-top item from the stack",
    OP_OVER = 0x3d; "Copies the second-to-top item to the top of the stack",
    OP_PICK = 0x3e; "Copies the nth-to-top item to the top of the stack, where n is the top item on the stack",
    OP_ROLL = 0x3f; "Moves the nth-to-top item to the top of the stack, where n is the top item on the stack",
    OP_ROT = 0x40; "Moves the third-to-top item to the top of the stack",
    OP_SWAP = 0x41; "Swaps the top two items on the stack",
    OP_TUCK = 0x42; "Copies the top item behind the second-to-top item on the stack",
    // splice
    OP_CAT = 0x50; "Concatenates the two strings on top of the stack",
    OP_SUBSTR = 0x51; "Extracts a substring from the third-to-top item on the stack",
    OP_LEFT = 0x52; "Extracts a left substring from the second-to-top item on the stack",
    OP_RIGHT = 0x53; "Extracts a right substring from the second-to-top item on the stack",
    OP_SIZE = 0x54; "Computes the size in bytes of the string on top of the stack",
    // bitwise logic
    OP_INVERT = 0x60; "Computes bitwise NOT of the number on top of the stack",
    OP_AND = 0x61; "Computes bitwise AND between the two numbers on top of the stack",
    OP_OR = 0x62; "Computes bitwise OR between the two numbers on top of the stack",
    OP_XOR = 0x63; "Computes bitwise XOR between the two numbers on top of the stack",
    OP_EQUAL = 0x64; "Substitutes the top two items on the stack with ONE if they are equal, with ZERO otherwise",
    OP_EQUALVERIFY = 0x65; "Computes OP_EQUAL and OP_VERIFY in sequence",
    // arithmetic
    OP_1ADD = 0x70; "Adds ONE to the number on top of the stack",
    OP_1SUB = 0x71; "Subtracts ONE from the number on top of the stack",
    OP_2MUL = 0x72; "Multiplies by TWO the number on top of the stack",
    OP_2DIV = 0x73; "Divides by TWO the number on top of the stack",
    OP_NOT = 0x74; "Substitutes the number on top of the stack with ONE if it is equal to ZERO, with ZERO otherwise",
    OP_0NOTEQUAL = 0x75; "Substitutes the number on top of the stack with ONE if it is not equal to ZERO, with ZERO otherwise",
    OP_ADD = 0x76; "Adds the two numbers on top of the stack",
    OP_SUB = 0x77; "Subtracts the number on top of the stack from the second-to-top number on the stack",
    OP_MUL = 0x78; "Multiplies the second-to-top number by the number on top of the stack",
    OP_DIV = 0x79; "Divides the second-to-top number by the number on top of the stack",
    OP_MOD = 0x7a; "Computes the remainder of the division of the second-to-top number by the number on top of the stack",
    OP_LSHIFT = 0x7b; "Computes the left shift of the second-to-top number by the number on top of the stack",
    OP_RSHIFT = 0x7c; "Computes the right shift of the second-to-top number by the number on top of the stack",
    OP_BOOLAND = 0x7d; "Substitutes the two numbers on top of the stack with ONE if they are both non-zero, with ZERO otherwise",
    OP_BOOLOR = 0x7e; "Substitutes the two numbers on top of the stack with ONE if they are not both ZERO, with ZERO otherwise",
    OP_NUMEQUAL = 0x7f; "Substitutes the two numbers on top of the stack with ONE if they are equal, with ZERO otherwise",
    OP_NUMEQUALVERIFY = 0x80; "Computes OP_NUMEQUAL and OP_VERIFY in sequence",
    OP_NUMNOTEQUAL = 0x81; "Substitutes the two numbers on top of the stack with ONE if they are not equal, with ZERO otherwise",
    OP_LESSTHAN = 0x82; "Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than the top item, with ZERO otherwise",
    OP_GREATERTHAN = 0x83; "Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than the top item, with ZERO otherwise",
    OP_LESSTHANOREQUAL = 0x84; "Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than or equal to the top item, with ZERO otherwise",
    OP_GREATERTHANOREQUAL = 0x85; "Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than or equal to the top item, with ZERO otherwise",
    OP_MIN = 0x86; "Substitutes the two numbers on top of the stack with the minimum between the two",
    OP_MAX = 0x87; "Substitutes the two numbers on top of the stack with the maximum between the two",
    OP_WITHIN = 0x88; "Substitutes the three numbers on top of the the stack with ONE if the third-to-top is greater or equal to the second-to-top and less than the top item, with ZERO otherwise",
    // crypto
    OP_SHA3 = 0x90; "Hashes the top item on the stack using SHA3-256",
    OP_HASH256 = 0x91; "Creates standard address from public key and pushes it onto the stack", // TODO: this is redundant, as OP_SHA3 already does the same thing
    OP_CHECKSIG = 0x94; "Pushes ONE onto the stack if the signature is valid, ZERO otherwise",
    OP_CHECKSIGVERIFY = 0x95; "Runs OP_CHECKSIG and OP_VERIFY in sequence",
    OP_CHECKMULTISIG = 0x96; "Pushes ONE onto the stack if the m-of-n multi-signature is valid, ZERO otherwise",
    OP_CHECKMULTISIGVERIFY = 0x97; "Runs OP_CHECKMULTISIG and OP_VERIFY in sequence",
    // smart data
    OP_CREATE = 0xa0; "",
    // reserved
    OP_NOP1 = 0xb0; "",
    OP_NOP2 = 0xb1; "",
    OP_NOP3 = 0xb2; "",
    OP_NOP4 = 0xb3; "",
    OP_NOP5 = 0xb4; "",
    OP_NOP6 = 0xb5; "",
    OP_NOP7 = 0xb6; "",
    OP_NOP8 = 0xb7; "",
    OP_NOP9 = 0xb8; "",
    OP_NOP10 = 0xb9; "",
    OP_NOP11 = 0x92; "", // Formerly OP_HASH256_V0
    OP_NOP12 = 0x93; "", // Formerly OP_HASH256_TEMP
    // constants
    <const_int_opcodes>
    // TODO: would be nice to add -1, maybe (should integers be signed?)
    OP_0(0) = 0x00,
    OP_1(1) = 0x01,
    OP_2(2) = 0x02,
    OP_3(3) = 0x03,
    OP_4(4) = 0x04,
    OP_5(5) = 0x05,
    OP_6(6) = 0x06,
    OP_7(7) = 0x07,
    OP_8(8) = 0x08,
    OP_9(9) = 0x09,
    OP_10(10) = 0x0a,
    OP_11(11) = 0x0b,
    OP_12(12) = 0x0c,
    OP_13(13) = 0x0d,
    OP_14(14) = 0x0e,
    OP_15(15) = 0x0f,
    OP_16(16) = 0x10,
    <variable_int_opcode>
    OP_NUM = 0x1f,
    // constant data
    <fixed_data_opcodes>
    OP_DATA1([u8; 1]) = 0xc1,
    OP_DATA2([u8; 2]) = 0xc2,
    OP_DATA4([u8; 4]) = 0xc3,
    OP_DATA8([u8; 8]) = 0xc4,
    OP_DATA16([u8; 16]) = 0xc5,
    OP_DATA32([u8; 32]) = 0xc6,
    OP_DATA64([u8; 64]) = 0xc7,
    <variable_data_opcode>
    OP_DATA(Vec<u8>) = 0xc0,
);

impl OpCodes {
    /// Returns true if the opcode is a conditional
    pub fn is_conditional(&self) -> bool {
        matches!(
            self,
            OpCodes::OP_IF | OpCodes::OP_NOTIF | OpCodes::OP_ELSE | OpCodes::OP_ENDIF
        )
    }
}

impl fmt::Display for ScriptEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Op(opcode) => f.write_str(opcode.to_name()),
            // TODO: jrabil: decide how to represent these as strings before merge
            Self::Int(int) => int.fmt(f),
            Self::Data(data) => write!(f, "0x{}", hex::encode(*data)),
        }
    }
}

impl fmt::Debug for ScriptEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Op(opcode) => f.debug_tuple("Op")
                .field(opcode)
                .finish(),
            Self::Int(int) => f.debug_tuple("Int")
                .field(int)
                .finish(),
            Self::Data(data) => f.debug_tuple("Data")
                .field(&format!("0x{}", hex::encode(*data)))
                .finish(),
        }
    }
}

make_error_type!(#[derive(Eq, PartialEq)] pub enum ScriptError {
    // opcode
    EmptyCondition; "Condition stack is empty",
    Verify; "The top item on the stack is ZERO",
    Burn; "OP_BURN executed",
    StackEmpty; "Not enough items on the stack",
    StackFull; "Too many items on the stack",
    ItemType; "Item type is not correct",
    StackIndexBounds(index: usize, length: usize);
            "Index {index} is out of bounds for stack of height {length}",
    IndexBounds(index: usize, length: usize);
            "Index {index} is out of bounds for operand of length {length}",
    SliceBounds(start: usize, n: usize, length: usize);
            "Index range [{start}..{start}+{n}] is out of bounds for operand of length {length}",
    ItemSize(size: usize, limit: usize); "Item size {size} exceeds {limit}-byte limit",
    ItemsNotEqual; "The two top items are not equal",
    Overflow; "Integer overflow",
    DivideByZero; "Attempt to divide by ZERO",
    InvalidSignature; "Signature is not valid",
    InvalidMultisignature; "Multi-signature is not valid",
    // TODO: jrabil these errors are confusing, we should return the actual error type
    NumPubkeys; "Number of public keys provided is not correct",
    NumSignatures; "Number of signatures provided is not correct",
    ReservedOpcode(op: OpCodes); "Reserved opcode: {op}",

    EndStackDepth(depth: usize); "Stack depth after script evaluation is not 1: {depth}",
    LastEntryIsZero; "Last stack entry is zero",
    NotEmptyCondition; "Condition stack after script evaluation is non-empty",
    // script
    Decode(cause: String); "Script failed to decode: {cause}",
    MaxScriptSize(size: usize); "Script size {size} exceeds {MAX_SCRIPT_SIZE}-byte limit",
    MaxScriptOps(count: usize); "Script opcode count {count} exceeds limit {MAX_OPS_PER_SCRIPT}",
    DuplicateElse; "Conditional block contains multiple OP_ELSE opcodes",
    BadMatchCount; "Script contained the wrong number of opcodes to match",
});
