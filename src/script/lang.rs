#![allow(unused)]

use std::convert::TryInto;
use std::fmt;
use std::fmt::Write;
use bincode::{Decode, Encode};
use fallible_iterator::FallibleIterator;
use crate::constants::*;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{
    PublicKey, Signature, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
};
use crate::script::interface_ops::*;
use crate::script::{OpCodes, ScriptEntry, ScriptError, StackEntry};
use crate::utils::transaction_utils::construct_address;
use serde::{Deserialize, Serialize};
use tracing::{error, trace, warn};
use crate::utils::serialize_utils::{bincode_borrow_decode_from_slice_standard, bincode_decode_from_slice_standard, bincode_encode_to_write_standard};
use crate::utils::ToName;

/// Stack for script execution
#[derive(Clone, Debug, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct Stack {
    pub main_stack: Vec<StackEntry>,
    pub alt_stack: Vec<StackEntry>,
    pub cond_stack: ConditionStack,
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl Stack {
    /// Creates a new stack
    pub fn new() -> Self {
        Self {
            main_stack: Vec::with_capacity(MAX_STACK_SIZE as usize),
            alt_stack: Vec::with_capacity(MAX_STACK_SIZE as usize),
            cond_stack: ConditionStack::new(),
        }
    }

    /// Checks if the stack is valid
    pub fn check_preconditions(&self) -> Result<(), ScriptError> {
        if self.main_stack.len() + self.alt_stack.len() > MAX_STACK_SIZE as usize {
            return Err(ScriptError::StackFull);
        }

        Self::check_entries_preconditions(&self.main_stack)?;
        Self::check_entries_preconditions(&self.alt_stack)
    }

    /// Checks that all entries in the given vector are valid
    fn check_entries_preconditions(entries: &Vec<StackEntry>) -> Result<(), ScriptError> {
        for entry in entries {
            Self::check_entry_preconditions(entry)?;
        }
        Ok(())
    }

    /// Checks that the given entry may be pushed on the stack
    fn check_entry_preconditions(entry: &StackEntry) -> Result<(), ScriptError> {
        match entry {
            StackEntry::Op(_) => return Err(ScriptError::ItemType),
            StackEntry::Bytes(s) => {
                if s.len() > MAX_SCRIPT_ITEM_SIZE as usize {
                    return Err(ScriptError::ItemSize(s.len(), MAX_SCRIPT_ITEM_SIZE as usize));
                }
            }
            _ => (),
        };
        Ok(())
    }

    /// Gets the current stack depth
    pub fn depth(&self) -> usize {
        self.main_stack.len()
    }

    /// Pops the top item from the stack
    pub fn pop(&mut self) -> Result<StackEntry, ScriptError> {
        self.main_stack.pop().ok_or(ScriptError::StackEmpty)
    }

    /// Pops the top item from the alt stack
    pub fn pop_alt(&mut self) -> Result<StackEntry, ScriptError> {
        self.alt_stack.pop().ok_or(ScriptError::StackEmpty)
    }

    /// Gets the top item from the stack without popping it
    pub fn peek(&self) -> Result<&StackEntry, ScriptError> {
        self.main_stack.last().ok_or(ScriptError::StackEmpty)
    }

    /// Returns the top item on the stack
    pub fn last(&self) -> Result<StackEntry, ScriptError> {
        self.peek().map(StackEntry::clone)
    }

    /// Checks if the current stack is a valid end state.
    pub fn check_end_state(&self) -> Result<(), ScriptError> {
        if !self.cond_stack.is_empty() {
            Err(ScriptError::NotEmptyCondition)
        } else if self.main_stack.len() != 1 {
            Err(ScriptError::EndStackDepth(self.main_stack.len()))
        } else if *self.main_stack.last().unwrap() == StackEntry::Num(0) {
            Err(ScriptError::LastEntryIsZero)
        } else {
            Ok(())
        }
    }

    /// Pushes a new entry onto the stack
    pub fn push(&mut self, stack_entry: StackEntry) -> Result<(), ScriptError> {
        Self::push_to(&mut self.main_stack, &self.alt_stack, stack_entry)
    }

    /// Pushes a new entry onto the stack
    pub fn push_alt(&mut self, stack_entry: StackEntry) -> Result<(), ScriptError> {
        Self::push_to(&mut self.alt_stack, &self.main_stack, stack_entry)
    }

    /// Pushes a new entry onto the stack
    fn push_to(dst: &mut Vec<StackEntry>, other: &Vec<StackEntry>, stack_entry: StackEntry) -> Result<(), ScriptError> {
        if dst.len() + other.len() >= MAX_STACK_SIZE as usize {
            return Err(ScriptError::StackFull);
        }

        Self::check_entry_preconditions(&stack_entry)?;
        dst.push(stack_entry);
        Ok(())
    }
}

impl From<Vec<StackEntry>> for Stack {
    /// Creates a new stack with a pre-filled main stack
    fn from(stack: Vec<StackEntry>) -> Self {
        Stack {
            main_stack: stack,
            alt_stack: Vec::with_capacity(MAX_STACK_SIZE as usize),
            cond_stack: ConditionStack::new(),
        }
    }
}

/// Stack for conditionals
#[derive(Clone, Debug, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConditionStack {
    pub size: usize,
    pub first_false_pos: Option<usize>,
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ConditionStack {
    /// Creates a new stack for conditionals
    pub fn new() -> Self {
        Self {
            size: ZERO,
            first_false_pos: None,
        }
    }

    /// Checks if all values are true
    pub fn all_true(&self) -> bool {
        self.first_false_pos.is_none()
    }

    /// Checks if the condition stack is empty
    pub fn is_empty(&self) -> bool {
        self.size == ZERO
    }

    /// Pushes a new value onto the condition stack
    pub fn push(&mut self, cond: bool) {
        if self.first_false_pos.is_none() && !cond {
            self.first_false_pos = Some(self.size);
        }
        self.size += ONE;
    }

    /// Pops the top value from the condition stack
    pub fn pop(&mut self) -> Result<(), ScriptError> {
        if self.is_empty() {
            return Err(ScriptError::EmptyCondition);
        }

        self.size -= ONE;
        if let Some(pos) = self.first_false_pos {
            if pos == self.size {
                self.first_false_pos.take();
            }
        }
        Ok(())
    }

    /// Toggles the top value on the condition stack
    pub fn toggle(&mut self) -> Result<(), ScriptError> {
        if self.is_empty() {
            return Err(ScriptError::EmptyCondition);
        }

        match self.first_false_pos {
            Some(pos) => {
                if pos == self.size - ONE {
                    self.first_false_pos = None;
                }
            }
            None => self.first_false_pos = Some(self.size - ONE),
        };
        Ok(())
    }
}

/// An iterator over a lazily decoded script.
#[derive(Clone, Debug)]
pub struct ScriptIterator<'a> {
    bytes: &'a [u8],
}

impl<'a> ScriptIterator<'a> {
    /// Gets a new `ScriptIterator` which will iterate over the script encoded in the given slice
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> FallibleIterator for ScriptIterator<'a> {
    type Item = ScriptEntry<'a>;
    type Error = ScriptError;

    /// Reads the next opcode in the script.
    ///
    /// Returns an error if an opcode failed to decode, or None if the end of the script has
    /// been reached.
    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.bytes.is_empty() {
            return Ok(None);
        }

        match bincode_borrow_decode_from_slice_standard::<ScriptEntry<'a>>(self.bytes) {
            Ok((opcode, read_bytes)) => {
                // Remove the first read_bytes from the slice
                self.bytes = self.bytes.split_at(read_bytes).1;
                Ok(Some(opcode))
            }
            Err(e) => Err(ScriptError::Decode(e.to_string())),
        }
    }
}

pub struct ScriptBuilder {
    buf: Vec<u8>,
}

impl ScriptBuilder {
    /// Creates a new `ScriptBuilder` with an empty initial state
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
        }
    }

    /// Appends the given `ScriptEntry` to the script
    ///
    /// ### Arguments
    ///
    /// * `entry` - the `ScriptEntry` to append
    pub fn push(&mut self, entry: &ScriptEntry) {
        bincode_encode_to_write_standard(entry, &mut self.buf)
            .expect("Failed to serialize script entry?!?");
    }

    /// Appends all of the given script entries to the script
    ///
    /// ### Arguments
    ///
    /// * `entries` - the script entries to append
    pub fn append_all(&mut self, entries: &[ScriptEntry]) {
        for entry in entries {
            self.push(entry);
        }
    }

    /// Appends the given opcode to the script
    ///
    /// ### Arguments
    ///
    /// * `op` - the opcode to append
    pub fn push_op(&mut self, op: OpCodes) {
        self.push(&ScriptEntry::Op(op))
    }

    /// Appends the given data constant to the script
    ///
    /// ### Arguments
    ///
    /// * `data` - the data to append
    pub fn push_data(&mut self, data: &[u8]) {
        self.push(&ScriptEntry::Data(data))
    }

    /// Appends the given integer constant to the script
    ///
    /// ### Arguments
    ///
    /// * `num` - the integer to append
    pub fn push_int(&mut self, int: u64) {
        self.push(&ScriptEntry::Int(int))
    }

    /// Finishes building the script, returning it as a `Script` object
    pub fn finish(self) -> Script {
        self.buf.into()
    }
}

/// Scripts are defined as a sequence of stack entries
/// NOTE: A tuple struct could probably work here as well
#[derive(Clone, PartialOrd, Eq, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct Script {
    script: Vec<u8>,
}

impl Script {
    /// Constructs a new script
    pub fn new() -> Self {
        Self { script: Vec::new() }
    }

    /// Creates a new script from the given script entries
    pub fn build(entries: &[ScriptEntry]) -> Self {
        let mut builder = ScriptBuilder::new();
        builder.append_all(entries);
        builder.finish()
    }

    /// Gets all the entries in this script.
    pub fn to_entries(&self) -> Result<Vec<ScriptEntry>, ScriptError> {
        ScriptIterator::new(&self.script).collect()
    }

    /// Checks if a script is valid
    pub fn verify(&self) -> Result<(), ScriptError> {
        if self.script.len() > MAX_SCRIPT_SIZE as usize {
            return Err(ScriptError::MaxScriptSize(self.script.len()));
        }

        let ops_count = ScriptIterator::new(&self.script)
            .filter(|entry| Ok(matches!(entry, ScriptEntry::Op(_))))
            .count()?; // number of opcodes in script
        if ops_count > MAX_OPS_PER_SCRIPT as usize {
            return Err(ScriptError::MaxScriptOps(ops_count));
        }

        // Make sure all IF/NOTIF opcodes have a matching ENDIF, and that there is exactly
        // 0 or 1 ELSE opcodes between them.
        let mut condition_stack : Vec<bool> = Vec::new();
        let mut itr = ScriptIterator::new(&self.script);
        while let Some(entry) = itr.next()? {
            match entry {
                ScriptEntry::Op(OpCodes::OP_IF | OpCodes::OP_NOTIF) => condition_stack.push(false),
                ScriptEntry::Op(OpCodes::OP_ELSE) => match condition_stack.last_mut() {
                    Some(seen_else) => {
                        if *seen_else {
                            return Err(ScriptError::DuplicateElse);
                        }
                        *seen_else = true;
                    },
                    None => return Err(ScriptError::EmptyCondition),
                },
                ScriptEntry::Op(OpCodes::OP_ENDIF) => match condition_stack.pop() {
                    Some(_) => (),
                    None => return Err(ScriptError::EmptyCondition),
                },
                _ => (),
            }
        }

        Ok(())
    }

    /// Interprets and executes a script
    pub fn interpret(&self) -> bool {
        self.interpret_full().is_ok()
    }

    /// Interprets and executes a script
    pub fn interpret_full(&self) -> Result<(), ScriptError> {
        self.verify()?;

        let mut stack = Stack::new();
        let mut itr = ScriptIterator::new(&self.script);
        while let Some(entry) = itr.next()? {
            match entry {
                /*---- OPCODE ----*/
                ScriptEntry::Op(op) => {
                    if !stack.cond_stack.all_true() && !op.is_conditional() {
                        // skip opcode if latest condition check failed
                        continue;
                    }

                    trace!("{}: {}", op.to_name(), op.desc());

                    match op {
                        // flow control
                        OpCodes::OP_NOP => op_nop(&mut stack),
                        OpCodes::OP_IF => op_if(&mut stack),
                        OpCodes::OP_NOTIF => op_notif(&mut stack),
                        OpCodes::OP_ELSE => op_else(&mut stack),
                        OpCodes::OP_ENDIF => op_endif(&mut stack),
                        OpCodes::OP_VERIFY => op_verify(&mut stack),
                        OpCodes::OP_BURN => op_burn(&mut stack),
                        // stack
                        OpCodes::OP_TOALTSTACK => op_toaltstack(&mut stack),
                        OpCodes::OP_FROMALTSTACK => op_fromaltstack(&mut stack),
                        OpCodes::OP_2DROP => op_2drop(&mut stack),
                        OpCodes::OP_2DUP => op_2dup(&mut stack),
                        OpCodes::OP_3DUP => op_3dup(&mut stack),
                        OpCodes::OP_2OVER => op_2over(&mut stack),
                        OpCodes::OP_2ROT => op_2rot(&mut stack),
                        OpCodes::OP_2SWAP => op_2swap(&mut stack),
                        OpCodes::OP_IFDUP => op_ifdup(&mut stack),
                        OpCodes::OP_DEPTH => op_depth(&mut stack),
                        OpCodes::OP_DROP => op_drop(&mut stack),
                        OpCodes::OP_DUP => op_dup(&mut stack),
                        OpCodes::OP_NIP => op_nip(&mut stack),
                        OpCodes::OP_OVER => op_over(&mut stack),
                        OpCodes::OP_PICK => op_pick(&mut stack),
                        OpCodes::OP_ROLL => op_roll(&mut stack),
                        OpCodes::OP_ROT => op_rot(&mut stack),
                        OpCodes::OP_SWAP => op_swap(&mut stack),
                        OpCodes::OP_TUCK => op_tuck(&mut stack),
                        // splice
                        OpCodes::OP_CAT => op_cat(&mut stack),
                        OpCodes::OP_SUBSTR => op_substr(&mut stack),
                        OpCodes::OP_LEFT => op_left(&mut stack),
                        OpCodes::OP_RIGHT => op_right(&mut stack),
                        OpCodes::OP_SIZE => op_size(&mut stack),
                        // bitwise logic
                        OpCodes::OP_INVERT => op_invert(&mut stack),
                        OpCodes::OP_AND => op_and(&mut stack),
                        OpCodes::OP_OR => op_or(&mut stack),
                        OpCodes::OP_XOR => op_xor(&mut stack),
                        OpCodes::OP_EQUAL => op_equal(&mut stack),
                        OpCodes::OP_EQUALVERIFY => op_equalverify(&mut stack),
                        // arithmetic
                        OpCodes::OP_1ADD => op_1add(&mut stack),
                        OpCodes::OP_1SUB => op_1sub(&mut stack),
                        OpCodes::OP_2MUL => op_2mul(&mut stack),
                        OpCodes::OP_2DIV => op_2div(&mut stack),
                        OpCodes::OP_NOT => op_not(&mut stack),
                        OpCodes::OP_0NOTEQUAL => op_0notequal(&mut stack),
                        OpCodes::OP_ADD => op_add(&mut stack),
                        OpCodes::OP_SUB => op_sub(&mut stack),
                        OpCodes::OP_MUL => op_mul(&mut stack),
                        OpCodes::OP_DIV => op_div(&mut stack),
                        OpCodes::OP_MOD => op_mod(&mut stack),
                        OpCodes::OP_LSHIFT => op_lshift(&mut stack),
                        OpCodes::OP_RSHIFT => op_rshift(&mut stack),
                        OpCodes::OP_BOOLAND => op_booland(&mut stack),
                        OpCodes::OP_BOOLOR => op_boolor(&mut stack),
                        OpCodes::OP_NUMEQUAL => op_numequal(&mut stack),
                        OpCodes::OP_NUMEQUALVERIFY => op_numequalverify(&mut stack),
                        OpCodes::OP_NUMNOTEQUAL => op_numnotequal(&mut stack),
                        OpCodes::OP_LESSTHAN => op_lessthan(&mut stack),
                        OpCodes::OP_GREATERTHAN => op_greaterthan(&mut stack),
                        OpCodes::OP_LESSTHANOREQUAL => op_lessthanorequal(&mut stack),
                        OpCodes::OP_GREATERTHANOREQUAL => op_greaterthanorequal(&mut stack),
                        OpCodes::OP_MIN => op_min(&mut stack),
                        OpCodes::OP_MAX => op_max(&mut stack),
                        OpCodes::OP_WITHIN => op_within(&mut stack),
                        // crypto
                        OpCodes::OP_SHA3 => op_sha3(&mut stack),
                        OpCodes::OP_HASH256 => op_hash256(&mut stack),
                        OpCodes::OP_CHECKSIG => op_checksig(&mut stack),
                        OpCodes::OP_CHECKSIGVERIFY => op_checksigverify(&mut stack),
                        OpCodes::OP_CHECKMULTISIG => op_checkmultisig(&mut stack),
                        OpCodes::OP_CHECKMULTISIGVERIFY => op_checkmultisigverify(&mut stack),
                        // smart data
                        OpCodes::OP_CREATE => Ok(()),
                        // reserved
                        op => Err(ScriptError::ReservedOpcode(op)),
                    }
                },
                /*---- INT | DATA ----*/
                ScriptEntry::Int(int) => {
                    if stack.cond_stack.all_true() {
                        stack.push(StackEntry::Num(int as usize))
                    } else {
                        Ok(())
                    }
                }
                ScriptEntry::Data(data) => {
                    if stack.cond_stack.all_true() {
                        stack.push(StackEntry::Bytes(data.to_vec()))
                    } else {
                        Ok(())
                    }
                },
            }?;

            stack.check_preconditions()?;
        }

        stack.check_end_state()
    }

    /// Constructs a new script for coinbase
    ///
    /// ### Arguments
    ///
    /// * `block_number`  - The block time to push
    pub fn new_for_coinbase(block_number: u64) -> Self {
        let mut builder = ScriptBuilder::new();
        builder.push_int(block_number);
        builder.finish()
    }

    /// Constructs a new script for an asset creation
    ///
    /// ### Arguments
    ///
    /// * `block_number`    - The block time
    /// * `asset_hash`      - The hash of the asset
    /// * `signature`       - The signature of the asset contents
    /// * `pub_key`         - The public key used in creating the signed content
    pub fn new_create_asset(
        block_number: u64,
        asset_hash: String,
        signature: Signature,
        pub_key: PublicKey,
    ) -> Self {
        let mut builder = ScriptBuilder::new();
        builder.push_op(OpCodes::OP_CREATE);
        builder.push_int(block_number);
        builder.push_op(OpCodes::OP_DROP);
        builder.push_data(&hex::decode(asset_hash).expect("asset_hash contains non-hex characters"));
        builder.push_data(signature.as_ref());
        builder.push_data(pub_key.as_ref());
        builder.push_op(OpCodes::OP_CHECKSIG);
        builder.finish()
    }

    /// Constructs a pay to public key hash script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Check data to provide signature
    /// * `signature`   - Signature of check data
    /// * `pub_key`     - Public key of the payer
    pub fn pay2pkh(
        check_data: Vec<u8>,
        signature: Signature,
        pub_key: PublicKey,
    ) -> Self {
        let mut builder = ScriptBuilder::new();
        builder.push_data(check_data.as_ref());
        builder.push_data(signature.as_ref());
        builder.push_data(pub_key.as_ref());
        builder.push_op(OpCodes::OP_DUP);
        builder.push_op(OpCodes::OP_HASH256);
        builder.push_data(&hex::decode(construct_address(&pub_key)).expect("address contains non-hex characters?"));
        builder.push_op(OpCodes::OP_EQUALVERIFY);
        builder.push_op(OpCodes::OP_CHECKSIG);
        builder.finish()
    }

    /// Constructs one part of a multiparty transaction script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Data to be signed for verification
    /// * `pub_key`     - Public key of this party
    /// * `signature`   - Signature of this party
    pub fn member_multisig(check_data: Vec<u8>, pub_key: PublicKey, signature: Signature) -> Self {
        let mut builder = ScriptBuilder::new();
        builder.push_data(check_data.as_ref());
        builder.push_data(signature.as_ref());
        builder.push_data(pub_key.as_ref());
        builder.push_op(OpCodes::OP_CHECKSIG);
        builder.finish()
    }

    /// Constructs a multisig locking script
    ///
    /// ### Arguments
    ///
    /// * `m`           - Number of signatures required to unlock
    /// * `check_data`  - Data to have checked against signatures
    /// * `pub_keys`    - The constituent public keys
    pub fn multisig_lock(m: usize, check_data: Vec<u8>, pub_keys: Vec<PublicKey>) -> Self {
        assert!(m <= pub_keys.len());

        let mut builder = ScriptBuilder::new();
        builder.push_data(check_data.as_ref());
        builder.push_int(m.try_into().unwrap());
        for pubkey in &pub_keys {
            builder.push_data(pubkey.as_ref());
        }
        builder.push_int(pub_keys.len().try_into().unwrap());
        builder.push_op(OpCodes::OP_CHECKMULTISIG);
        builder.finish()
    }

    /// Constructs a multisig unlocking script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Data to have signed
    /// * `signatures`  - Signatures to unlock with
    pub fn multisig_unlock(check_data: Vec<u8>, signatures: Vec<Signature>) -> Self {
        let mut builder = ScriptBuilder::new();
        builder.push_data(check_data.as_ref());
        for signature in &signatures {
            builder.push_data(signature.as_ref());
        }
        builder.finish()
    }

    /// Constructs a multisig validation script
    ///
    /// ### Arguments
    ///
    /// * `m`           - Number of signatures to assure validity
    /// * `n`           - Number of public keys that are valid
    /// * `signatures`  - Signatures to validate
    /// * `pub_keys`    - Public keys to validate
    pub fn multisig_validation(
        check_data: Vec<u8>,
        signatures: Vec<Signature>,
        pub_keys: Vec<PublicKey>,
    ) -> Self {
        assert!(signatures.len() <= pub_keys.len());

        let mut builder = ScriptBuilder::new();
        builder.push_data(check_data.as_ref());
        for signature in &signatures {
            builder.push_data(signature.as_ref());
        }
        builder.push_int(signatures.len().try_into().unwrap());
        for pubkey in &pub_keys {
            builder.push_data(pubkey.as_ref());
        }
        builder.push_int(pub_keys.len().try_into().unwrap());
        builder.push_op(OpCodes::OP_CHECKMULTISIG);
        builder.finish()
    }
}

impl From<Vec<u8>> for Script {
    /// Creates a new script from the given opcodes
    fn from(script: Vec<u8>) -> Self {
        Script { script }
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for res in ScriptIterator::new(&self.script).iterator() {
            if !first {
                f.write_char(' ')?;
            }
            match res {
                Ok(entry) => fmt::Display::fmt(&entry, f)?,
                Err(err) => {
                    f.write_str("<decode error>")?;
                    return Err(fmt::Error);
                },
            };
        }
        Ok(())
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct Inner<'a>(&'a [u8]);
        impl fmt::Debug for Inner<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let mut list = f.debug_list();
                for res in ScriptIterator::new(self.0).iterator() {
                    match res {
                        Ok(entry) => list.entry(&entry),
                        Err(err) => {
                            list.entry(&"<decode error>").entry(&err);
                            break;
                        },
                    };
                }
                list.finish()
            }
        }

        f.debug_tuple("Script")
            .field(&Inner(&self.script))
            .finish()
    }
}
