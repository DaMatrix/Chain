#![allow(unused)]
use crate::constants::*;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{
    self as sign, PublicKey, Signature, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
};
use crate::primitives::asset::{Asset, AssetValues, ItemAsset, TokenAmount};
use crate::primitives::druid::DruidExpectation;
use crate::primitives::transaction::*;
use crate::script::interface_ops::*;
use crate::script::lang::{ConditionStack, Script, Stack};
use crate::script::{OpCodes, ScriptEntry, ScriptError, StackEntry};
use crate::utils::transaction_utils::{
    construct_address, construct_tx_hash, construct_tx_in_out_signable_hash,
    construct_tx_in_signable_asset_hash, construct_tx_in_signable_hash,
};
use ring::error;
use std::collections::{BTreeMap, BTreeSet};
use std::thread::current;
use tracing::{debug, error, info, trace};
use crate::utils::array_match_slice_copy;

use super::transaction_utils::construct_p2sh_address;

/// Verifies that all incoming transactions are allowed to be spent. Returns false if a single
/// transaction doesn't verify
///
/// TODO: Currently assumes p2pkh and p2sh, abstract to all tx types
///
/// ### Arguments
///
/// * `tx`                   - Transaction to verify
/// * `current_block_number` - Current block number
/// * `is_in_utxo`           - Function to check if a `TxOut` is in the UTXO set
pub fn tx_is_valid<'a>(
    tx: &Transaction,
    current_block_number: u64,
    is_in_utxo: impl Fn(&OutPoint) -> Option<&'a TxOut> + 'a,
) -> bool {
    let mut tx_ins_spent: AssetValues = Default::default();
    // TODO: Add support for `Data` asset variant
    // `Item` assets MUST have an a DRS value associated with them when they are getting on-spent

    debug!("tx: {:?}", tx.outputs);
    if tx.outputs.iter().any(|out| {
        debug!("out is item: {:?}", out.value.is_item());
        debug!("out has drs: {:?}", out.value.get_genesis_hash().is_none());
        debug!("out has metadata: {:?}", out.value.get_metadata().is_some());

        (out.value.is_item()
            && (out.value.get_genesis_hash().is_none() || out.value.get_metadata().is_some()))
    }) {
        error!("ON-SPENDING NEEDS EMPTY METADATA AND NON-EMPTY DRS SPECIFICATION");
        return false;
    }

    for tx_in in &tx.inputs {

        let full_tx_hash = construct_tx_in_out_signable_hash(tx_in, &tx.outputs);
        println!("full_tx_hash: {:?}", full_tx_hash);

        
        // Ensure the transaction is in the `UTXO` set
        let tx_out_point = match tx_in.previous_out.as_ref() {
            Some(v) => v,
            None => {
                error!("TRANSACTION DOESN'T CONTAIN PREVIOUS OUTPOINT");
                return false;
            }
        };

        let tx_out = if let Some(tx_out) = is_in_utxo(tx_out_point) {
            tx_out
        } else {
            error!("UTXO DOESN'T CONTAIN THIS TX");
            return false;
        };

        // Check locktime
        if tx_out.locktime > current_block_number {
            error!("LOCKTIME NOT MET");
            return false;
        }

        // At this point `TxIn` will be valid
        let tx_out_pk = tx_out.script_public_key.as_ref();
        let tx_out_hash = construct_tx_in_signable_hash(tx_out_point);
        let full_tx_hash = construct_tx_in_out_signable_hash(tx_in, &tx.outputs);

        debug!("full_tx_hash: {:?}", full_tx_hash);

        if let Some(pk) = tx_out_pk {
            // Check will need to include other signature types here
            if !tx_has_valid_p2pkh_sig(&tx_in.script_signature, &full_tx_hash, pk)
                && !tx_has_valid_p2sh_script(&tx_in.script_signature, pk)
            {
                error!("INVALID SIGNATURE OR SCRIPT TYPE");
                return false;
            }
        } else {
            return false;
        }

        let asset = tx_out.value.clone().with_fixed_hash(tx_out_point);
        tx_ins_spent.update_add(&asset);
    }

    debug!(
        "txs are valid: {:?}",
        tx_outs_are_valid(&tx.outputs, &tx.fees, tx_ins_spent.clone())
    );

    tx_outs_are_valid(&tx.outputs, &tx.fees, tx_ins_spent)
}

/// Verifies that the outgoing `TxOut`s are valid. Returns false if a single
/// transaction doesn't verify.
///
/// TODO: Abstract to data assets
///
/// ### Arguments
///
/// * `tx_outs`      - `TxOut`s to verify
/// * `tx_ins_spent` - Total amount spendable from `TxIn`s
pub fn tx_outs_are_valid(tx_outs: &[TxOut], fees: &[TxOut], tx_ins_spent: AssetValues) -> bool {
    let mut tx_outs_spent: AssetValues = Default::default();

    for tx_out in tx_outs {
        // Addresses must have valid length
        if let Some(addr) = &tx_out.script_public_key {
            if !address_has_valid_length(addr) {
                trace!("Address has invalid length");
                return false;
            }
        }

        tx_outs_spent.update_add(&tx_out.value);
    }

    // Check fees as well
    for fee in fees {
        // Addresses must have valid length
        if let Some(addr) = &fee.script_public_key {
            if !address_has_valid_length(addr) {
                trace!("Address has invalid length");
                return false;
            }
        }

        tx_outs_spent.update_add(&fee.value);
    }

    // Ensure that the `TxIn`s correlate with the `TxOut`s
    tx_outs_spent.is_equal(&tx_ins_spent)
}

pub enum MatchV6Script<'a> {
    Coinbase { 
        block_number: u64,
    },
    Create {
        block_number: u64,
        asset_hash: &'a [u8],
        signature: Signature,
        public_key: PublicKey,
    },
    P2PKH {
        check_data: &'a [u8],
        signature: Signature,
        public_key: PublicKey,
        public_key_hash: &'a [u8],
    },
}

/// Checks if a script matches any of the known v6 script patterns and extracts the relevant fields.
///
/// ### Arguments
///
/// * `script`      - Script to match
pub fn match_v6_script(script: &Script) -> Result<MatchV6Script, Script> {
    if let Some(block_number) = match_coinbase_script(script) {
        Ok(MatchV6Script::Coinbase { block_number })
    } else if let Some((check_data, signature, public_key, public_key_hash)) = match_p2pkh_script(script) {
        Ok(MatchV6Script::P2PKH { check_data, signature, public_key, public_key_hash })
    } else if let Some((block_number, asset_hash, signature, public_key)) = match_create_script(script) {
        Ok(MatchV6Script::Create { block_number, asset_hash, signature, public_key })
    } else {
        Err(script.clone())
    }
}

/// Checks if a script matches the coinbase pattern and extracts the relevant fields.
///
/// ### Arguments
///
/// * `script`      - Script to match
pub fn match_coinbase_script(
    script: &Script,
) -> Option<u64> {
    if let Some([
                ScriptEntry::Int(block_number),
                ]) = array_match_slice_copy(&script.to_entries().ok()?) {
        Some(block_number)
    } else {
        None
    }
}

/// Checks if a script matches the item creation pattern and extracts the relevant fields.
///
/// ### Arguments
///
/// * `script`      - Script to match
pub fn match_create_script(
    script: &Script,
) -> Option<(u64, &[u8], Signature, PublicKey)> {
    if let Some([
                ScriptEntry::Op(OpCodes::OP_CREATE),
                ScriptEntry::Int(block_number),
                ScriptEntry::Op(OpCodes::OP_DROP),
                ScriptEntry::Data(b),
                ScriptEntry::Data(signature),
                ScriptEntry::Data(public_key),
                ScriptEntry::Op(OpCodes::OP_CHECKSIG),
                ]) = array_match_slice_copy(&script.to_entries().ok()?) {
        Some((
            block_number,
            b,
            Signature::from_slice(signature)?,
            PublicKey::from_slice(public_key)?,
        ))
    } else {
        None
    }
}

/// Checks whether a create transaction has a valid input script
///
/// ### Arguments
///
/// * `script`      - Script to validate
/// * `asset`       - Asset to be created
pub fn tx_has_valid_create_script(script: &Script, asset: &Asset) -> bool {
    let asset_hash = construct_tx_in_signable_asset_hash(asset);

    if let Asset::Item(r) = asset {
        if !item_has_valid_size(r) {
            trace!("Item metadata is too large");
            return false;
        }
    }

    if let Some((_, b, _, _)) = match_create_script(script) {
        // For legacy reasons, the hashed data is the hex representation of the data rather than
        // the data itself.
        let b_hex = hex::encode(b);

        if b_hex == asset_hash && script.interpret() {
            return true;
        }
    }

    trace!("Invalid script for create: {:?}", script);
    false
}

/// Checks if a script matches the P2PKH pattern and extracts the relevant fields.
///
/// ### Arguments
///
/// * `script`      - Script to match
pub fn match_p2pkh_script(
    script: &Script,
) -> Option<(&[u8], Signature, PublicKey, &[u8])> {
    if let Some([
                ScriptEntry::Data(check_data),
                ScriptEntry::Data(signature),
                ScriptEntry::Data(public_key),
                ScriptEntry::Op(OpCodes::OP_DUP),
                ScriptEntry::Op(OpCodes::OP_HASH256),
                ScriptEntry::Data(public_key_hash),
                ScriptEntry::Op(OpCodes::OP_EQUALVERIFY),
                ScriptEntry::Op(OpCodes::OP_CHECKSIG),
                ]) = array_match_slice_copy(&script.to_entries().ok()?) {
        Some((
            check_data,
            Signature::from_slice(signature)?,
            PublicKey::from_slice(public_key)?,
            public_key_hash,
        ))
    } else {
        None
    }
}

/// Checks whether a transaction to spend tokens in P2PKH has a valid signature
///
/// ### Arguments
///
/// * `script`          - Script to validate
/// * `outpoint_hash`   - Hash of the corresponding outpoint
/// * `tx_out_pub_key`  - Public key of the previous tx_out
// TODO: The last two operands should be converted to the corresponding types
fn tx_has_valid_p2pkh_sig(script: &Script, outpoint_hash: &str, tx_out_pub_key: &str) -> bool {
    debug!("script: {:?}", script);

    if let Some((b, _, _, h)) = match_p2pkh_script(script) {
        debug!("b: {:?}, h: {:?}", b, h);

        // For legacy reasons, the hashed data is the hex representation of the data rather than
        // the data itself.
        let h_hex = hex::encode(h);
        let b_hex = hex::encode(b);

        if h_hex == tx_out_pub_key && b_hex == outpoint_hash && script.interpret() {
            return true;
        }
    }

    trace!(
        "Invalid P2PKH script: {:?} tx_out_pub_key: {}",
        script,
        tx_out_pub_key
    );

    false
}

/// Checks whether a transaction to spend tokens in P2SH has a valid hash and executing script
///
/// ### Arguments
///
/// * `script`          - Script to validate
/// * `address`         - Address of the P2SH transaction
pub fn tx_has_valid_p2sh_script(script: &Script, address: &str) -> bool {
    let p2sh_address = construct_p2sh_address(script);

    if p2sh_address == address {
        return script.interpret();
    }

    trace!(
        "Invalid P2SH script: {:?}, address: {}",
        script,
        address
    );

    false
}

/// Checks that a item's metadata conforms to the network size constraint
///
/// ### Arguments
///
/// * `item` - Item to check
fn item_has_valid_size(item: &ItemAsset) -> bool {
    if let Some(metadata) = &item.metadata {
        return metadata.len() <= MAX_METADATA_BYTES;
    }
    true
}

/// Checks that an address has a valid length
///
/// ### Arguments
///
/// * `address` - Address to check
fn address_has_valid_length(address: &str) -> bool {
    address.len() == 32 || address.len() == 64
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use crate::constants::ITEM_ACCEPT_VAL;
    use crate::primitives::asset::Asset;
    use crate::primitives::druid::DdeValues;
    use crate::primitives::transaction::OutPoint;
    use crate::utils::Placeholder;
    use crate::utils::test_utils::generate_tx_with_ins_and_outs_assets;
    use crate::utils::transaction_utils::*;

    /*---- FLOW CONTROL OPS ----*/

    #[test]
    /// Test OP_NOP
    fn test_nop() {
        /// op_nop([1]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_nop(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_nop([]) -> []
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![];
        op_nop(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_IF
    fn test_if() {
        /// op_if([1], {0,None}) -> [], {1,None}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        op_if(&mut stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(stack.cond_stack.size, 1);
        assert_eq!(stack.cond_stack.first_false_pos, None);
        /// op_if([0], {0,None}) -> [], {1,0}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        op_if(&mut stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(stack.cond_stack.size, 1);
        assert_eq!(stack.cond_stack.first_false_pos, Some(0));
        /// op_if([1], {1,0}) -> [1], {2,0}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.cond_stack.size = 1;
        stack.cond_stack.first_false_pos = Some(0);
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_if(&mut stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(stack.cond_stack.size, 2);
        assert_eq!(stack.cond_stack.first_false_pos, Some(0));
        /// error item type
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(Vec::new()));
        let b = op_if(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
        /// error num items
        let mut stack = Stack::new();
        let b = op_if(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_NOTIF
    fn test_notif() {
        /// op_notif([0], {0,None}) -> [], {1,None}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        op_notif(&mut stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(stack.cond_stack.size, 1);
        assert_eq!(stack.cond_stack.first_false_pos, None);
        /// op_notif([1], {0,None}) -> [], {1,0}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        op_notif(&mut stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(stack.cond_stack.size, 1);
        assert_eq!(stack.cond_stack.first_false_pos, Some(0));
        /// op_notif([0], {1,0}) -> [0], {2,0}
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        stack.cond_stack.size = 1;
        stack.cond_stack.first_false_pos = Some(0);
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_notif(&mut stack);
        assert_eq!(stack.main_stack, v);
        assert_eq!(stack.cond_stack.size, 2);
        assert_eq!(stack.cond_stack.first_false_pos, Some(0));
        /// error item type
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(Vec::new()));
        let b = op_notif(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
        /// error num items
        let mut stack = Stack::new();
        let b = op_notif(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_ELSE
    fn test_else() {
        /// op_else({1,None}) -> {1,0}
        let mut stack = Stack::new();
        stack.cond_stack.size = 1;
        stack.cond_stack.first_false_pos = None;
        op_else(&mut stack);
        assert_eq!(stack.cond_stack.size, 1);
        assert_eq!(stack.cond_stack.first_false_pos, Some(0));
        /// op_else({1,0}) -> {1,None}
        let mut stack = Stack::new();
        stack.cond_stack.size = 1;
        stack.cond_stack.first_false_pos = Some(0);
        op_else(&mut stack);
        assert_eq!(stack.cond_stack.size, 1);
        assert_eq!(stack.cond_stack.first_false_pos, None);
        /// op_else({2,0}) -> {2,0}
        let mut stack = Stack::new();
        stack.cond_stack.size = 2;
        stack.cond_stack.first_false_pos = Some(0);
        op_else(&mut stack);
        assert_eq!(stack.cond_stack.size, 2);
        assert_eq!(stack.cond_stack.first_false_pos, Some(0));
        /// empty condition stack
        let mut stack = Stack::new();
        let b = op_else(&mut stack);
        assert_eq!(b, Err(ScriptError::EmptyCondition))
    }

    #[test]
    /// Test OP_ENDIF
    fn test_endif() {
        /// op_endif({1,None}) -> {0,None}
        let mut stack = Stack::new();
        stack.cond_stack.size = 1;
        stack.cond_stack.first_false_pos = None;
        op_endif(&mut stack);
        assert_eq!(stack.cond_stack.size, 0);
        assert_eq!(stack.cond_stack.first_false_pos, None);
        /// op_endif({1,0}) -> {0,None}
        let mut stack = Stack::new();
        stack.cond_stack.size = 1;
        stack.cond_stack.first_false_pos = Some(0);
        op_endif(&mut stack);
        assert_eq!(stack.cond_stack.size, 0);
        assert_eq!(stack.cond_stack.first_false_pos, None);
        /// op_endif({2,0}) -> {1,0}
        let mut stack = Stack::new();
        stack.cond_stack.size = 2;
        stack.cond_stack.first_false_pos = Some(0);
        op_endif(&mut stack);
        assert_eq!(stack.cond_stack.size, 1);
        assert_eq!(stack.cond_stack.first_false_pos, Some(0));
        /// empty condition stack
        let mut stack = Stack::new();
        let b = op_endif(&mut stack);
        assert_eq!(b, Err(ScriptError::EmptyCondition))
    }

    #[test]
    /// Test OP_VERIFY
    fn test_verify() {
        /// op_verify([1]) -> []
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        op_verify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_verify([0]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let b = op_verify(&mut stack);
        assert_eq!(b, Err(ScriptError::Verify));
        /// op_verify([]) -> fail
        let mut stack = Stack::new();
        let b = op_verify(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_BURN
    fn test_burn() {
        /// op_burn([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_burn(&mut stack);
        assert_eq!(b, Err(ScriptError::Burn));
        /// op_burn([]) -> fail
        let mut stack = Stack::new();
        let b = op_burn(&mut stack);
        assert_eq!(b, Err(ScriptError::Burn))
    }

    /*---- STACK OPS ----*/

    #[test]
    /// Test OP_TOALTSTACK
    fn test_toaltstack() {
        /// op_toaltstack([1], []) -> [], [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v1: Vec<StackEntry> = vec![];
        let mut v2: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_toaltstack(&mut stack);
        assert_eq!(stack.main_stack, v1);
        assert_eq!(stack.alt_stack, v2);
        /// op_toaltstack([], []) -> fail
        let mut stack = Stack::new();
        let b = op_toaltstack(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_FROMALTSTACK
    fn test_fromaltstack() {
        /// op_fromaltstack([], [1]) -> [1], []
        let mut stack = Stack::new();
        stack.alt_stack.push(StackEntry::Num(1));
        let mut v1: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v2: Vec<StackEntry> = vec![];
        op_fromaltstack(&mut stack);
        assert_eq!(stack.main_stack, v1);
        assert_eq!(stack.alt_stack, v2);
        /// op_fromaltstack([], []) -> fail
        let mut stack = Stack::new();
        let b = op_fromaltstack(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_2DROP
    fn test_2drop() {
        /// op_2drop([1,2]) -> []
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        op_2drop(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2drop([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_2drop(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_2DUP
    fn test_2dup() {
        /// op_2dup([1,2]) -> [1,2,1,2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2dup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2dup([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_2dup(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_3DUP
    fn test_3dup() {
        /// op_3dup([1,2,3]) -> [1,2,3,1,2,3]
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        op_3dup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_3dup([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_3dup(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_2OVER
    fn test_2over() {
        /// op_2over([1,2,3,4]) -> [1,2,3,4,1,2]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2over(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2over([1,2,3]) -> fail
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_2over(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_2ROT
    fn test_2rot() {
        /// op_2rot([1,2,3,4,5,6]) -> [3,4,5,6,1,2]
        let mut stack = Stack::new();
        for i in 1..=6 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 3..=6 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2rot(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2rot([1,2,3,4,5]) -> fail
        let mut stack = Stack::new();
        for i in 1..=5 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_2rot(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_2SWAP
    fn test_2swap() {
        /// op_2swap([1,2,3,4]) -> [3,4,1,2]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 3..=4 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2swap(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2swap([1,2,3]) -> fail
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_2swap(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_IFDUP
    fn test_ifdup() {
        /// op_ifdup([1]) -> [1,1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(1));
        }
        op_ifdup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_ifdup([0]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_ifdup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_ifdup([]) -> fail
        let mut stack = Stack::new();
        let b = op_ifdup(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_DEPTH
    fn test_depth() {
        /// op_depth([1,1,1,1]) -> [1,1,1,1,4]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(1));
        }
        v.push(StackEntry::Num(4));
        op_depth(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_depth([]) -> [0]
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_depth(&mut stack);
        assert_eq!(stack.main_stack, v)
    }

    #[test]
    /// Test OP_DROP
    fn test_drop() {
        /// op_drop([1]) -> []
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![];
        op_drop(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_drop([]) -> fail
        let mut stack = Stack::new();
        let b = op_drop(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_DUP
    fn test_dup() {
        /// op_dup([1]) -> [1,1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(1));
        }
        op_dup(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_dup([]) -> fail
        let mut stack = Stack::new();
        let b = op_dup(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_NIP
    fn test_nip() {
        /// op_nip([1,2]) -> [2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_nip(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_nip([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_nip(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_OVER
    fn test_over() {
        /// op_over([1,2]) -> [1,2,1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_over(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_over([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_over(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty))
    }

    #[test]
    /// Test OP_PICK
    fn test_pick() {
        /// op_pick([1,2,3,4,3]) -> [1,2,3,4,1]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_pick(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_pick([1,2,3,4,0]) -> [1,2,3,4,4]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(4));
        op_pick(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_pick([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_pick(&mut stack);
        assert_eq!(b, Err(ScriptError::StackIndexBounds(1, 0)));
        /// op_pick([1,"hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        let b = op_pick(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
        /// op_pick([1,1]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_pick(&mut stack);
        assert_eq!(b, Err(ScriptError::StackIndexBounds(2, 1)));
    }

    #[test]
    /// Test OP_ROLL
    fn test_roll() {
        /// op_roll([1,2,3,4,3]) -> [2,3,4,1]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        for i in 2..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_roll(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_roll([1,2,3,4,0]) -> [1,2,3,4]
        let mut stack = Stack::new();
        for i in 1..=4 {
            stack.push(StackEntry::Num(i));
        }
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        op_roll(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_roll([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_roll(&mut stack);
        assert_eq!(b, Err(ScriptError::StackIndexBounds(1, 0)));
        /// op_roll([1,"hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        let b = op_roll(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
        /// op_roll([1,1]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_roll(&mut stack);
        assert_eq!(b, Err(ScriptError::StackIndexBounds(2, 1)));
    }

    #[test]
    /// Test OP_ROT
    fn test_rot() {
        /// op_rot([1,2,3]) -> [2,3,1]
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 2..=3 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_rot(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_rot([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_rot(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_SWAP
    fn test_swap() {
        /// op_swap([1,2]) -> [2,1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2), StackEntry::Num(1)];
        op_swap(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_swap([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_swap(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_TUCK
    fn test_tuck() {
        /// op_tuck([1,2]) -> [2,1,2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_tuck(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_tuck([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_tuck(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    /*---- SPLICE OPS ----*/

    #[test]
    /// Test OP_CAT
    fn test_cat() {
        /// op_cat(["hello","world"]) -> ["helloworld"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Bytes("world".as_bytes().to_vec()));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("helloworld".as_bytes().to_vec())];
        op_cat(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_cat(["hello",""]) -> ["hello"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Bytes("".as_bytes().to_vec()));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".as_bytes().to_vec())];
        op_cat(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_cat(["a","a"*MAX_SCRIPT_ITEM_SIZE]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("a".as_bytes().to_vec()));
        let mut s = String::new();
        for i in 1..=MAX_SCRIPT_ITEM_SIZE {
            s.push('a');
        }
        stack.push(StackEntry::Bytes(s.as_bytes().to_vec()));
        let b = op_cat(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemSize(1 + MAX_SCRIPT_ITEM_SIZE as usize, MAX_SCRIPT_ITEM_SIZE as usize)));
        /// op_cat(["hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        let b = op_cat(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
        /// op_cat(["hello", 1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(1));
        let b = op_cat(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
    }

    #[test]
    /// Test OP_SUBSTR
    fn test_substr() {
        /// op_substr(["hello",1,2]) -> ["el"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("el".as_bytes().to_vec())];
        op_substr(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_substr(["hello",0,0]) -> [""]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        for i in 1..=2 {
            stack.push(StackEntry::Num(0));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".as_bytes().to_vec())];
        op_substr(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_substr(["hello",0,5]) -> ["hello"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".as_bytes().to_vec())];
        op_substr(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_substr(["hello",5,0]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(5));
        stack.push(StackEntry::Num(0));
        let b = op_substr(&mut stack);
        assert_eq!(b, Err(ScriptError::SliceBounds(5, 0, 5)));
        /// op_substr(["hello",1,5]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(5));
        let b = op_substr(&mut stack);
        assert_eq!(b, Err(ScriptError::SliceBounds(1, 5, 5)));
        /// op_substr(["hello",1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(1));
        let b = op_substr(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
        /// op_substr(["hello",1,usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_substr(&mut stack);
        assert_eq!(b, Err(ScriptError::SliceBounds(1, usize::MAX, 5)));
        /// op_substr(["hello",1,""]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Bytes("".as_bytes().to_vec()));
        let b = op_substr(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
    }

    #[test]
    /// Test OP_LEFT
    fn test_left() {
        /// op_left(["hello",2]) -> ["he"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(2));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("he".as_bytes().to_vec())];
        op_left(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_left(["hello",0]) -> [""]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".as_bytes().to_vec())];
        op_left(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_left(["hello",5]) -> ["hello"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".as_bytes().to_vec())];
        op_left(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_left(["hello",""]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Bytes("".as_bytes().to_vec()));
        let b = op_left(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
        /// op_left(["hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        let b = op_left(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
    }

    #[test]
    /// Test OP_RIGHT
    fn test_right() {
        /// op_right(["hello",0]) -> ["hello"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".as_bytes().to_vec())];
        op_right(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_right(["hello",2]) -> ["llo"]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(2));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("llo".as_bytes().to_vec())];
        op_right(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_right(["hello",5]) -> [""]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".as_bytes().to_vec())];
        op_right(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_right(["hello",""]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        stack.push(StackEntry::Bytes("".as_bytes().to_vec()));
        let b = op_right(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
        /// op_right(["hello"]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        let b = op_right(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
    }

    #[test]
    /// Test OP_SIZE
    fn test_size() {
        /// op_size(["hello"]) -> ["hello",5]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        let mut v: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".as_bytes().to_vec()), StackEntry::Num(5)];
        op_size(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_size([""]) -> ["",0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes("".as_bytes().to_vec()));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".as_bytes().to_vec()), StackEntry::Num(0)];
        op_size(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_size([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_size(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
        /// op_size([]) -> fail
        let mut stack = Stack::new();
        let b = op_size(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    /*---- BITWISE LOGIC OPS ----*/

    #[test]
    /// Test OP_INVERT
    fn test_invert() {
        /// op_invert([0]) -> [usize::MAX]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(usize::MAX)];
        op_invert(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_invert([]) -> fail
        let mut stack = Stack::new();
        let b = op_invert(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_AND
    fn test_and() {
        /// op_and([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_and(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_and([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_and(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_OR
    fn test_or() {
        /// op_or([1,2]) -> [3]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_or(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_or([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_or(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_XOR
    fn test_xor() {
        /// op_xor([1,2]) -> [3]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_xor(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_xor([1,1]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_xor(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_xor([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_xor(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_EQUAL
    fn test_equal() {
        /// op_equal(["hello","hello"]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_equal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_equal([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_equal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_equal([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_equal(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_EQUALVERIFY
    fn test_equalverify() {
        /// op_equalverify(["hello","hello"]) -> []
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Bytes("hello".as_bytes().to_vec()));
        }
        let mut v: Vec<StackEntry> = vec![];
        op_equalverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_equalverify([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_equalverify(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemsNotEqual));
        /// op_equalverify([1]) -> fail
        let mut stack = Stack::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_equalverify(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    /*---- ARITHMETIC OPS ----*/

    #[test]
    /// Test OP_1ADD
    fn test_1add() {
        /// op_1add([1]) -> [2]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_1add(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_1add([usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_1add(&mut stack);
        assert_eq!(b, Err(ScriptError::Overflow));
        /// op_1add([]) -> fail
        let mut stack = Stack::new();
        let b = op_1add(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_1SUB
    fn test_1sub() {
        /// op_1sub([1]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_1sub(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_1sub([0]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let b = op_1sub(&mut stack);
        assert_eq!(b, Err(ScriptError::Overflow));
        /// op_1sub([]) -> fail
        let mut stack = Stack::new();
        let b = op_1sub(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_2MUL
    fn test_2mul() {
        /// op_2mul([1]) -> [2]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_2mul(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2mul([usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_2mul(&mut stack);
        assert_eq!(b, Err(ScriptError::Overflow));
        /// op_2mul([]) -> fail
        let mut stack = Stack::new();
        let b = op_2mul(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_2DIV
    fn test_2div() {
        /// op_2div([1]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_2div(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_2div([]) -> fail
        let mut stack = Stack::new();
        let b = op_2div(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_NOT
    fn test_not() {
        /// op_not([0]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_not(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_not([1]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_not(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_not([]) -> fail
        let mut stack = Stack::new();
        let b = op_not(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_0NOTEQUAL
    fn test_0notequal() {
        /// op_0notequal([1]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_0notequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_0notequal([0]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_0notequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_0notequal([]) -> fail
        let mut stack = Stack::new();
        let b = op_0notequal(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_ADD
    fn test_add() {
        /// op_add([1,2]) -> [3]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_add(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_add([1,usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_add(&mut stack);
        assert_eq!(b, Err(ScriptError::Overflow));
        /// op_add([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_add(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_SUB
    fn test_sub() {
        /// op_sub([1,0]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_sub(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_sub([0,1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::Num(1));
        let b = op_sub(&mut stack);
        assert_eq!(b, Err(ScriptError::Overflow));
        /// op_sub([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_sub(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_MUL
    fn test_mul() {
        /// op_mul([1,2]) -> [2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_mul(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_mul([2,usize::MAX]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::Num(usize::MAX));
        let b = op_mul(&mut stack);
        assert_eq!(b, Err(ScriptError::Overflow));
        /// op_mul([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_mul(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_DIV
    fn test_div() {
        /// op_div([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_div(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_div([1,0]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(0));
        let b = op_div(&mut stack);
        assert_eq!(b, Err(ScriptError::DivideByZero));
        /// op_div([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_div(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_MOD
    fn test_mod() {
        /// op_mod([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_mod(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_mod([1,0]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(0));
        let b = op_mod(&mut stack);
        assert_eq!(b, Err(ScriptError::DivideByZero));
        /// op_mod([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_mod(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_LSHIFT
    fn test_lshift() {
        /// op_lshift([1,2]) -> [4]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(4)];
        op_lshift(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lshift([1,64]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(64));
        let b = op_lshift(&mut stack);
        assert_eq!(b, Err(ScriptError::DivideByZero));
        /// op_lshift([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_lshift(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_RSHIFT
    fn test_rshift() {
        /// op_rshift([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_rshift(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_rshift([1,64]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(64));
        let b = op_rshift(&mut stack);
        assert_eq!(b, Err(ScriptError::DivideByZero));
        /// op_rshift([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_rshift(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_BOOLAND
    fn test_booland() {
        /// op_booland([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_booland(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_booland([0,1]) -> [0]
        let mut stack = Stack::new();
        for i in 0..=1 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_booland(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_booland([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_booland(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_BOOLOR
    fn test_boolor() {
        /// op_boolor([0,1]) -> [1]
        let mut stack = Stack::new();
        for i in 0..=1 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_boolor(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_boolor([0,0]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(0));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_boolor(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_boolor([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_boolor(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_NUMEQUAL
    fn test_numequal() {
        /// op_numequal([1,1]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_numequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numequal([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_numequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numequal([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_numequal(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_NUMEQUALVERIFY
    fn test_numequalverify() {
        /// op_numequalverify([1,1]) -> []
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![];
        op_numequalverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numequalverify([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_numequalverify(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemsNotEqual));
        /// op_numequalverify([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_numequalverify(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_NUMNOTEQUAL
    fn test_numnotequal() {
        /// op_numnotequal([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_numnotequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numnotequal([1,1]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_numnotequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_numnotequal([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_numnotequal(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_LESSTHAN
    fn test_lessthan() {
        /// op_lessthan([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_lessthan(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lessthan([1,1]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_lessthan(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lessthan([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_lessthan(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_GREATERTHAN
    fn test_greaterthan() {
        /// op_greaterthan([2,1]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_greaterthan(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_greaterthan([1,1]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_greaterthan(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_greaterthan([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_greaterthan(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_LESSTHANOREQUAL
    fn test_lessthanorequal() {
        /// test_lessthanorequal([1,1]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_lessthanorequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lessthanorequal([2,1]) -> [0]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_lessthanorequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_lessthanorequal([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_lessthanorequal(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_GREATERTHANOREQUAL
    fn test_greaterthanorequal() {
        /// op_greaterthanorequal([1,1]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_greaterthanorequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_greaterthanorequal([1,2]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_greaterthanorequal(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_greaterthanorequal([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_greaterthanorequal(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_MIN
    fn test_min() {
        /// op_min([1,2]) -> [1]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_min(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_min([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_min(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_MAX
    fn test_max() {
        /// op_max([1,2]) -> [2]
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_max(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_max([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_max(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_WITHIN
    fn test_within() {
        /// op_within([2,1,3]) -> [1]
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_within(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_within([1,2,3]) -> [0]
        let mut stack = Stack::new();
        for i in 1..=3 {
            stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_within(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_within([1,2]) -> fail
        let mut stack = Stack::new();
        for i in 1..=2 {
            stack.push(StackEntry::Num(i));
        }
        let b = op_within(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    /*---- CRYPTO OPS ----*/

    #[test]
    /// Test OP_SHA3
    fn test_sha3() {
        /// op_sha3([sig]) -> [sha3_256(sig)]
        let (pk, sk) = sign::gen_keypair().unwrap();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig = sign::sign_detached(msg.as_bytes(), &sk);
        let h = sha3_256::digest(sig.as_ref()).to_vec();
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes(h)];
        op_sha3(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_sha3([pk]) -> [sha3_256(pk)]
        let h = sha3_256::digest(pk.as_ref()).to_vec();
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes(h)];
        op_sha3(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_sha3(["hello"]) -> [sha3_256("hello")]
        let s = "hello".as_bytes().to_vec();
        let h = sha3_256::digest(hex::encode(&s).as_bytes()).to_vec();
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(s));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes(h)];
        op_sha3(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_sha3([1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(1));
        let b = op_sha3(&mut stack);
        assert_eq!(b, Err(ScriptError::ItemType));
        /// op_sha3([]) -> fail
        let mut stack = Stack::new();
        let b = op_sha3(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_HASH256
    fn test_hash256() {
        /// op_hash256([pk]) -> [addr]
        let (pk, sk) = sign::gen_keypair().unwrap();
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes(hex::decode(construct_address(&pk)).unwrap())];
        op_hash256(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// op_hash256([]) -> fail
        let mut stack = Stack::new();
        let b = op_hash256(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_CHECKSIG
    fn test_checksig() {
        /// op_checksig([msg,sig,pk]) -> [1]
        let (pk, sk) = sign::gen_keypair().unwrap();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig = sign::sign_detached(msg.as_bytes(), &sk);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checksig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong message
        /// op_checksig([msg',sig,pk]) -> [0]
        let msg = hex::encode(vec![0, 0, 1]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checksig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong public key
        /// op_checksig([msg,sig,pk']) -> [0]
        let (pk, sk) = sign::gen_keypair().unwrap();
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checksig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// no message
        /// op_checksig([sig,pk]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let b = op_checksig(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_CHECKSIGVERIFY
    fn test_checksigverify() {
        /// op_checksigverify([msg,sig,pk]) -> []
        let (pk, sk) = sign::gen_keypair().unwrap();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig = sign::sign_detached(msg.as_bytes(), &sk);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![];
        op_checksigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong message
        /// op_checksigverify([msg',sig,pk]) -> fail
        let msg = hex::encode(vec![0, 0, 1]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let b = op_checksigverify(&mut stack);
        assert_eq!(b, Err(ScriptError::Verify));
        /// wrong public key
        /// op_checksig([msg,sig,pk']) -> fail
        let (pk, sk) = sign::gen_keypair().unwrap();
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let b = op_checksigverify(&mut stack);
        assert_eq!(b, Err(ScriptError::Verify));
        /// no message
        /// op_checksigverify([sig,pk]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig));
        stack.push(StackEntry::PubKey(pk));
        let b = op_checksigverify(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_CHECKMULTISIG
    fn test_checkmultisig() {
        /// 2-of-3 multisig
        /// op_checkmultisig([msg,sig1,sig2,2,pk1,pk2,pk3,3]) -> [1]
        let (pk1, sk1) = sign::gen_keypair().unwrap();
        let (pk2, sk2) = sign::gen_keypair().unwrap();
        let (pk3, sk3) = sign::gen_keypair().unwrap();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig1 = sign::sign_detached(msg.as_bytes(), &sk1);
        let sig2 = sign::sign_detached(msg.as_bytes(), &sk2);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 0-of-3 multisig
        /// op_checkmultisig([msg,0,pk1,pk2,pk3,3]) -> [1]
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 0-of-0 multisig
        /// op_checkmultisig([msg,0,0]) -> [1]
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 1-of-1 multisig
        /// op_checkmultisig([msg,sig1,1,pk1,1]) -> [1]
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// ordering is not relevant
        /// op_checkmultisig([msg,sig3,sig1,2,pk2,pk3,pk1,3]) -> [1]
        let msg = hex::encode(vec![0, 0, 0]);
        let sig3 = sign::sign_detached(msg.as_bytes(), &sk3);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig3));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong message
        /// op_checkmultisig([msg',sig1,sig2,2,pk1,pk2,pk3,3]) -> [0]
        let msg = hex::encode(vec![0, 0, 1]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// same signature twice
        /// op_checkmultisig([msg,sig1,sig1,2,pk1,pk2,pk3,3]) -> [0]
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checkmultisig(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// too many pubkeys
        /// op_checkmultisig([MAX_PUB_KEYS_PER_MULTISIG+1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(MAX_PUB_KEYS_PER_MULTISIG as usize + ONE));
        let b = op_checkmultisig(&mut stack);
        assert_eq!(b, Err(ScriptError::NumPubkeys));
        /// not enough pubkeys
        /// op_checkmultisig([pk1,pk2,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut stack);
        assert_eq!(b, Err(ScriptError::NumPubkeys));
        /// too many signatures
        /// op_checkmultisig([4,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(4));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut stack);
        assert_eq!(b, Err(ScriptError::NumSignatures));
        /// not enough signatures
        /// op_checkmultisig([sig1,2,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut stack);
        assert_eq!(b, Err(ScriptError::NumSignatures));
        /// no message
        /// op_checkmultisig([sig1,sig2,2,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    /// Test OP_CHECKMULTISIGVERIFY
    fn test_checkmultisigverify() {
        /// 2-of-3 multisig
        /// op_checkmultisigverify([msg,sig1,sig2,2,pk1,pk2,pk3,3]) -> []
        let (pk1, sk1) = sign::gen_keypair().unwrap();
        let (pk2, sk2) = sign::gen_keypair().unwrap();
        let (pk3, sk3) = sign::gen_keypair().unwrap();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig1 = sign::sign_detached(msg.as_bytes(), &sk1);
        let sig2 = sign::sign_detached(msg.as_bytes(), &sk2);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 0-of-3 multisig
        /// op_checkmultisigverify([msg,0,pk1,pk2,pk3,3]) -> []
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 0-of-0 multisig
        /// op_checkmultisig([msg,0,0]) -> []
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Num(0));
        stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// 1-of-1 multisig
        /// op_checkmultisigverify([msg,sig1,1,pk1,1]) -> []
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(1));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// ordering is not relevant
        /// op_checkmultisigverify([msg,sig3,sig1,2,pk2,pk3,pk1,3]) -> []
        let msg = hex::encode(vec![0, 0, 0]);
        let sig3 = sign::sign_detached(msg.as_bytes(), &sk3);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig3));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// wrong message
        /// op_checkmultisigverify([msg',sig1,sig2,2,pk1,pk2,pk3,3]) -> fail
        let msg = hex::encode(vec![0, 0, 1]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert_eq!(b, Err(ScriptError::Verify));
        /// same signature twice
        /// op_checkmultisigverify([msg,sig1,sig1,2,pk1,pk2,pk3,3]) -> fail
        let msg = hex::encode(vec![0, 0, 0]);
        let mut stack = Stack::new();
        stack.push(StackEntry::Bytes(hex::decode(msg).unwrap()));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        op_checkmultisigverify(&mut stack);
        assert_eq!(stack.main_stack, v);
        /// too many pubkeys
        /// op_checkmultisigverify([MAX_PUB_KEYS_PER_MULTISIG+1]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(MAX_PUB_KEYS_PER_MULTISIG as usize + ONE));
        let b = op_checkmultisigverify(&mut stack);
        assert_eq!(b, Err(ScriptError::NumPubkeys));
        /// not enough pubkeys
        /// op_checkmultisigverify([pk1,pk2,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert_eq!(b, Err(ScriptError::NumPubkeys));
        /// too many signatures
        /// op_checkmultisigverify([4,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Num(4));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert_eq!(b, Err(ScriptError::NumSignatures));
        /// not enough signatures
        /// op_checkmultisigverify([sig1,2,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert_eq!(b, Err(ScriptError::NumSignatures));
        /// no message
        /// op_checkmultisigverify([sig1,sig2,2,pk1,pk2,pk3,3]) -> fail
        let mut stack = Stack::new();
        stack.push(StackEntry::Signature(sig1));
        stack.push(StackEntry::Signature(sig2));
        stack.push(StackEntry::Num(2));
        stack.push(StackEntry::PubKey(pk1));
        stack.push(StackEntry::PubKey(pk2));
        stack.push(StackEntry::PubKey(pk3));
        stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut stack);
        assert_eq!(b, Err(ScriptError::StackEmpty));
    }

    #[test]
    fn test_is_valid_script() {
        // empty script
        let v = &[];
        let script = Script::build(v);
        assert_eq!(script.verify(), Ok(()));
        // script length <= 10000 bytes
        let long_str = &[('a' as u8); 248];
        let v = &[ScriptEntry::Data(long_str); 40];
        let script = Script::build(v);
        assert_eq!(script.verify(), Ok(()));
        // script length > 10000 bytes
        let v = &([
            (&[ScriptEntry::Data(long_str); 40]) as &[ScriptEntry],
            (&[ScriptEntry::Op(OpCodes::OP_NOP)]) as &[ScriptEntry],
        ].concat());
        let script = Script::build(v);
        assert_eq!(script.verify(), Err(ScriptError::MaxScriptSize(10001)));
        // # pushes <= 201
        let v = &[ScriptEntry::Int(1); MAX_OPS_PER_SCRIPT as usize];
        let script = Script::build(v);
        assert_eq!(script.verify(), Ok(()));
        // # pushes > 201
        let v = &[ScriptEntry::Int(1); (MAX_OPS_PER_SCRIPT + 1) as usize];
        let script = Script::build(v);
        assert_eq!(script.verify(), Ok(()));
        // # opcodes <= 201
        let v = &[ScriptEntry::Op(OpCodes::OP_NOP); MAX_OPS_PER_SCRIPT as usize];
        let script = Script::build(v);
        assert_eq!(script.verify(), Ok(()));
        // # opcodes > 201
        let v = &[ScriptEntry::Op(OpCodes::OP_NOP); (MAX_OPS_PER_SCRIPT + 1) as usize];
        let script = Script::build(v);
        assert_eq!(script.verify(), Err(ScriptError::MaxScriptOps((MAX_OPS_PER_SCRIPT + 1) as usize)));
    }

    #[test]
    fn test_is_valid_stack() {
        // empty stack
        let v = vec![];
        let stack = Stack::from(v);
        assert_eq!(stack.check_preconditions(), Ok(()));
        // # items on interpreter stack <= 1000
        let v = vec![StackEntry::Num(1); MAX_STACK_SIZE as usize];
        let stack = Stack::from(v);
        assert_eq!(stack.check_preconditions(), Ok(()));
        // # items on interpreter stack > 1000
        let v = vec![StackEntry::Num(1); (MAX_STACK_SIZE + 1) as usize];
        let stack = Stack::from(v);
        assert_eq!(stack.check_preconditions(), Err(ScriptError::StackFull));
    }

    #[test]
    fn test_interpret_script() {
        // empty script
        let v = &[];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::EndStackDepth(0)));
        // OP_0
        let v = &[ScriptEntry::Int(0)];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::LastEntryIsZero));
        // OP_1
        let v = &[ScriptEntry::Int(1)];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Ok(()));
        // OP_1 OP_2 OP_ADD OP_3 OP_EQUAL
        let v = &[
            ScriptEntry::Int(1),
            ScriptEntry::Int(2),
            ScriptEntry::Op(OpCodes::OP_ADD),
            ScriptEntry::Int(3),
            ScriptEntry::Op(OpCodes::OP_EQUAL),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Ok(()));
        // script length <= 10000 bytes
        let long_str = &[('a' as u8); 248];
        let v = &[ScriptEntry::Data(long_str); 40];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::EndStackDepth(40)));
        // script length > 10000 bytes
        let v = &([
            (&[ScriptEntry::Data(long_str); 40]) as &[ScriptEntry],
            (&[ScriptEntry::Op(OpCodes::OP_NOP)]) as &[ScriptEntry],
        ].concat());
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::MaxScriptSize(10001)));
        // # pushes <= 201
        let v = &[ScriptEntry::Int(1); MAX_OPS_PER_SCRIPT as usize];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::EndStackDepth(MAX_OPS_PER_SCRIPT as usize)));
        // # pushes > 201
        let v = &[ScriptEntry::Int(1); (MAX_OPS_PER_SCRIPT + 1) as usize];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::EndStackDepth((MAX_OPS_PER_SCRIPT + 1) as usize)));
        // # opcodes <= 201
        let v = &[ScriptEntry::Op(OpCodes::OP_NOP); MAX_OPS_PER_SCRIPT as usize];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::EndStackDepth(0)));
        // # opcodes > 201
        let v = &[ScriptEntry::Op(OpCodes::OP_NOP); (MAX_OPS_PER_SCRIPT + 1) as usize];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::MaxScriptOps((MAX_OPS_PER_SCRIPT + 1) as usize)));
        // # items on interpreter stack <= 1000
        let v = &[ScriptEntry::Int(1); MAX_STACK_SIZE as usize];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::EndStackDepth(MAX_STACK_SIZE as usize)));
        // # items on interpreter stack > 1000
        let v = &[ScriptEntry::Int(1); (MAX_STACK_SIZE + 1) as usize];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::StackFull));
    }

    #[test]
    fn test_conditionals() {
        // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ELSE OP_0 OP_ENDIF
        let v = &[
            ScriptEntry::Int(1),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(2),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(3),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::DuplicateElse));
        // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let v = &[
            ScriptEntry::Int(1),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(2),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(3),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Ok(()));
        // OP_1 OP_IF OP_0 OP_ELSE OP_3 OP_ENDIF
        let v = &[
            ScriptEntry::Int(1),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(3),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::LastEntryIsZero));
        // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        let v = &[
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(2),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(3),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Ok(()));
        // OP_0 OP_IF OP_2 OP_ELSE OP_0 OP_ENDIF
        let v = &[
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(2),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::LastEntryIsZero));
        // OP_0 OP_NOTIF OP_2 OP_ELSE OP_0 OP_ENDIF
        let v = &[
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_NOTIF),
            ScriptEntry::Int(2),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Ok(()));
        // OP_0 OP_IF OP_2 OP_ENDIF
        let v = &[
            ScriptEntry::Int(1),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::LastEntryIsZero));
        // OP_1 OP_IF OP_2 OP_IF OP_3 OP_ELSE OP_0 OP_ENDIF OP_ENDIF
        let v = &[
            ScriptEntry::Int(1),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(2),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(3),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Ok(()));
        // OP_1 OP_IF OP_0 OP_IF OP_3 OP_ELSE OP_0 OP_ENDIF OP_ENDIF
        let v = &[
            ScriptEntry::Int(1),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(3),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::LastEntryIsZero));
        // OP_0 OP_IF OP_2 OP_IF OP_3 OP_ELSE OP_4 OP_ENDIF OP_ELSE OP_0 OP_ENDIF
        let v = &[
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(2),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(3),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(4),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::LastEntryIsZero));
        // OP_1 OP_IF OP_1
        let v = &[
            ScriptEntry::Int(1),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(1),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::NotEmptyCondition));
        // OP_1 OP_IF OP_1 OP_ELSE OP_3
        let v = &[
            ScriptEntry::Int(1),
            ScriptEntry::Op(OpCodes::OP_IF),
            ScriptEntry::Int(1),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(3),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::NotEmptyCondition));
        // OP_2 OP_ELSE OP_3 OP_ENDIF
        let v = &[
            ScriptEntry::Int(2),
            ScriptEntry::Op(OpCodes::OP_ELSE),
            ScriptEntry::Int(3),
            ScriptEntry::Op(OpCodes::OP_ENDIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::EmptyCondition));
        // OP_0 OP_IF
        let v = &[
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_IF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::NotEmptyCondition));
        // OP_IF
        let v = &[ScriptEntry::Op(OpCodes::OP_IF)];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::StackEmpty));
        // OP_0 OP_NOTIF
        let v = &[
            ScriptEntry::Int(0),
            ScriptEntry::Op(OpCodes::OP_NOTIF),
        ];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::NotEmptyCondition));
        // OP_NOTIF
        let v = &[ScriptEntry::Op(OpCodes::OP_NOTIF)];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::StackEmpty));
        // OP_ELSE
        let v = &[ScriptEntry::Op(OpCodes::OP_ELSE)];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::EmptyCondition));
        // OP_ENDIF
        let v = &[ScriptEntry::Op(OpCodes::OP_ENDIF)];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::EmptyCondition));
    }

    #[test]
    fn test_burn_script() {
        let v = &[ScriptEntry::Op(OpCodes::OP_BURN)];
        let script = Script::build(v);
        assert_eq!(script.interpret_full(), Err(ScriptError::Burn));
    }

    /// Util function to create p2pkh TxIns
    fn create_multisig_tx_ins(tx_values: Vec<TxConstructor>, m: usize) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();

        for entry in tx_values {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::multisig_validation(
                entry.previous_out.t_hash.as_ref().to_vec(),
                entry.signatures,
                entry.pub_keys,
            );
            new_tx_in.previous_out = Some(entry.previous_out);

            tx_ins.push(new_tx_in);
        }

        tx_ins
    }

    /// Util function to create multisig member TxIns
    fn create_multisig_member_tx_ins(tx_values: Vec<TxConstructor>) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();

        for entry in tx_values {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::member_multisig(
                // TODO: is this check_data correct?
                entry.previous_out.t_hash.as_ref().to_vec(),
                entry.pub_keys[0],
                entry.signatures[0],
            );
            new_tx_in.previous_out = Some(entry.previous_out);

            tx_ins.push(new_tx_in);
        }

        tx_ins
    }

    #[test]
    /// Checks that a correct create script is validated as such
    fn test_pass_create_script_valid() {
        let asset = Asset::item(1, None, None);
        let asset_hash = construct_tx_in_signable_asset_hash(&asset);
        let (pk, sk) = sign::gen_keypair().unwrap();
        let signature = sign::sign_detached(asset_hash.as_bytes(), &sk);

        let script = Script::new_create_asset(0, asset_hash, signature, pk);
        assert!(tx_has_valid_create_script(&script, &asset),
                "invalid create script: {:?}", script);
    }

    #[test]
    /// Checks that metadata is validated correctly if too large
    fn test_fail_create_item_script_invalid() {
        let metadata = String::from_utf8_lossy(&[0; MAX_METADATA_BYTES + 1]).to_string();
        let asset = Asset::item(1, None, Some(metadata));
        let asset_hash = construct_tx_in_signable_asset_hash(&asset);
        let (pk, sk) = sign::gen_keypair().unwrap();
        let signature = sign::sign_detached(asset_hash.as_bytes(), &sk);

        let script = Script::new_create_asset(0, asset_hash, signature, pk);
        assert!(!tx_has_valid_create_script(&script, &asset),
                "invalid create asset script: {:?}", script);
    }

    #[test]
    /// Checks whether addresses are validated correctly
    fn test_validate_addresses_correctly() {
        let (pk, _) = sign::gen_keypair().unwrap();
        let address = construct_address(&pk);

        assert!(address_has_valid_length(&address));
        assert!(address_has_valid_length(&hex::encode([0; 32])));
        assert!(!address_has_valid_length(&hex::encode([0; 64])));
    }

    #[test]
    /// Checks that correct member multisig scripts are validated as such
    fn test_pass_member_multisig_valid() {
        let (pk, sk) = sign::gen_keypair().unwrap();
        let t_hash = TxHash::placeholder();
        let signature = sign::sign_detached(hex::encode(t_hash.as_ref()).as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new_from_hash(t_hash, 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert_eq!(tx_ins[0].clone().script_signature.interpret_full(), Ok(()));
    }

    #[test]
    /// Checks that incorrect member multisig scripts are validated as such
    fn test_fail_member_multisig_invalid() {
        let (_pk, sk) = sign::gen_keypair().unwrap();
        let (pk, _sk) = sign::gen_keypair().unwrap();
        let t_hash = TxHash::placeholder();
        let signature = sign::sign_detached(t_hash.as_ref(), &sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new_from_hash(t_hash, 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert_eq!(tx_ins[0].clone().script_signature.interpret_full(), Err(ScriptError::LastEntryIsZero));
    }

    #[test]
    /// Checks that correct p2pkh transaction signatures are validated as such
    fn test_pass_p2pkh_sig_valid() {
        let (pk, sk) = sign::gen_keypair().unwrap();
        let outpoint = OutPoint::placeholder();
        let mut key_material = BTreeMap::new();
        key_material.insert(outpoint.clone(), (pk, sk));

        let tx_const = TxConstructor {
            previous_out: outpoint,
            signatures: vec![],
            pub_keys: vec![pk],
        };

        let tx_outs = vec![];
        let mut tx_ins = construct_payment_tx_ins(vec![tx_const]);
        tx_ins = update_input_signatures(&tx_ins, &tx_outs, &key_material);

        let hash_to_sign = construct_tx_in_out_signable_hash(&tx_ins[0], &tx_outs);
        let tx_out_pk = construct_address(&pk);

        assert!(tx_has_valid_p2pkh_sig(
            &tx_ins[0].script_signature,
            &hash_to_sign,
            &tx_out_pk
        ));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_invalid() {
        let (pk, sk) = sign::gen_keypair().unwrap();
        let (second_pk, _s) = sign::gen_keypair().unwrap();
        let outpoint = OutPoint::placeholder();

        let hash_to_sign = construct_tx_in_signable_hash(&outpoint);
        let signature = sign::sign_detached(hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: outpoint,
            signatures: vec![signature],
            pub_keys: vec![second_pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let tx_out_pk = construct_address(&pk);

        assert!(!tx_has_valid_p2pkh_sig(
            &tx_ins[0].script_signature,
            &hash_to_sign,
            &tx_out_pk
        ));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_script_empty() {
        let (pk, sk) = sign::gen_keypair().unwrap();
        let outpoint = OutPoint::placeholder();

        let hash_to_sign = construct_tx_in_signable_hash(&outpoint);
        let signature = sign::sign_detached(hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: outpoint,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let mut tx_ins = Vec::new();

        for entry in [tx_const] {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::new();
            new_tx_in.previous_out = Some(entry.previous_out);

            tx_ins.push(new_tx_in);
        }

        let tx_out_pk = construct_address(&pk);

        assert!(!tx_has_valid_p2pkh_sig(
            &tx_ins[0].script_signature,
            &hash_to_sign,
            &tx_out_pk
        ));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn test_fail_p2pkh_sig_script_invalid_struct() {
        let (pk, sk) = sign::gen_keypair().unwrap();
        let outpoint = OutPoint::placeholder();

        let hash_to_sign = construct_tx_in_signable_hash(&outpoint);
        let signature = sign::sign_detached(hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: outpoint,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let mut tx_ins = Vec::new();

        for entry in [tx_const] {
            let mut new_tx_in = TxIn::new();
            // TODO: jrabil: re-do this before merge
            new_tx_in.script_signature = Script::pay2pkh(
                Vec::new(),
                signature.clone(),
                pk.clone(),
            );
            /*new_tx_in.script_signature = Script::new();
            new_tx_in
                .script_signature
                .stack
                .push(StackEntry::Bytes("".as_bytes().to_vec()));*/
            new_tx_in.previous_out = Some(entry.previous_out);

            tx_ins.push(new_tx_in);
        }

        let tx_out_pk = construct_address(&pk);

        assert!(!tx_has_valid_p2pkh_sig(
            &tx_ins[0].script_signature,
            &hash_to_sign,
            &tx_out_pk
        ));
    }

    #[test]
    /// Checks that correct multisig validation signatures are validated as such
    fn test_pass_multisig_validation_valid() {
        let (first_pk, first_sk) = sign::gen_keypair().unwrap();
        let (second_pk, second_sk) = sign::gen_keypair().unwrap();
        let (third_pk, third_sk) = sign::gen_keypair().unwrap();
        let check_data = TxHash::placeholder();

        let m = 2;
        let first_sig = sign::sign_detached(hex::encode(check_data.as_ref()).as_bytes(), &first_sk);
        let second_sig = sign::sign_detached(hex::encode(check_data.as_ref()).as_bytes(), &second_sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new_from_hash(check_data, 0),
            signatures: vec![first_sig, second_sig],
            pub_keys: vec![first_pk, second_pk, third_pk],
        };

        let tx_ins = create_multisig_tx_ins(vec![tx_const], m);

        assert_eq!(tx_ins[0].clone().script_signature.interpret_full(), Ok(()),
                   "multisig script_signature invalid: {:?}", tx_ins[0].script_signature);
    }

    #[test]
    /// Validate tx_is_valid for multiple TxIn configurations
    fn test_tx_is_valid() {
        test_tx_is_valid_common(None, false);
    }

    #[test]
    /// Validate tx_is_valid for locktime
    fn test_tx_is_valid_locktime() {
        assert!(
            test_tx_is_valid_common(Some(99), false)
                && !test_tx_is_valid_common(Some(1000000000), false)
        );
    }

    #[test]
    /// Validate tx_is_valid for fees
    fn test_tx_is_valid_fees() {
        test_tx_is_valid_common(None, true);
    }

    fn test_tx_is_valid_common(
        locktime: Option<u64>,
        with_fees: bool,
    ) -> bool {
        //
        // Arrange
        //
        let (pk, sk) = sign::gen_keypair().unwrap();
        let tx_outpoint = OutPoint::placeholder();
        let script_public_key = construct_address(&pk);
        let tx_in_previous_out =
            TxOut::new_token_amount(script_public_key.clone(), TokenAmount(5), locktime);
        let ongoing_tx_outs = vec![tx_in_previous_out.clone()];
        let tx_in = TxIn {
            script_signature: Script::new(),
            previous_out: Some(tx_outpoint.clone()),
        };

        let valid_bytes = construct_tx_in_out_signable_hash(&tx_in, &ongoing_tx_outs.clone());
        let valid_sig = sign::sign_detached(valid_bytes.as_bytes(), &sk);

        // Test cases:
        let inputs = [
            // 0. Happy case: valid test
            (
                Script::build(&[
                    ScriptEntry::Data(&hex::decode(valid_bytes).unwrap()),
                    ScriptEntry::Data(valid_sig.as_ref()),
                    ScriptEntry::Data(pk.as_ref()),
                    ScriptEntry::Op(OpCodes::OP_DUP),
                    ScriptEntry::Op(OpCodes::OP_HASH256),
                    ScriptEntry::Data(&hex::decode(script_public_key).unwrap()),
                    ScriptEntry::Op(OpCodes::OP_EQUALVERIFY),
                    ScriptEntry::Op(OpCodes::OP_CHECKSIG),
                ]),
                true,
            ),
            // 2. Empty script
            (Script::build(&[ScriptEntry::Data(&[])]), false),
        ];

        //
        // Act
        //
        let mut actual_result = Vec::new();
        for (script, _) in &inputs {
            let tx_ins = vec![TxIn {
                script_signature: script.clone(),
                previous_out: Some(tx_outpoint.clone()),
            }];

            let tx = Transaction {
                inputs: tx_ins,
                outputs: ongoing_tx_outs.clone(),
                ..Default::default()
            };

            let result = tx_is_valid(&tx, 500000000, |v| {
                Some(&tx_in_previous_out).filter(|_| v == &tx_outpoint)
            });
            actual_result.push(result);
        }

        actual_result == inputs.iter().map(|(_, e)| *e).collect::<Vec<bool>>()
    }

    #[test]
    /// ### Test Case 1
    ///
    ///  - *Tokens only*
    /// -  *Success*
    ///
    /// 1. Inputs contain two `TxIn`s for `Token`s of amounts `3` and `2`
    /// 2. Outputs contain `TxOut`s for `Token`s of amounts `3` and `2`
    fn test_tx_drs_tokens_only_success() {
        test_tx_drs_common(
            &[(3, None, None), (2, None, None)],
            &[(3, None), (2, None)],
            true,
        );
    }

    #[test]
    /// ### Test Case 2
    ///
    ///  - *Tokens only*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Token`s of amounts `3` and `2`
    /// 2. Outputs contain `TxOut`s for `Token`s of amounts `3` and `3`
    /// 3. `TxIn` `Token`s amount does not match `TxOut` `Token`s amount
    fn test_tx_drs_tokens_only_failure_amount_mismatch() {
        test_tx_drs_common(
            &[(3, None, None), (2, None, None)],
            &[(3, None), (3, None)],
            false,
        );
    }

    #[test]
    /// ### Test Case 3
    ///
    ///  - *Items only*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Item`s of amount `3` and `2` with different `genesis_hash` values
    /// 2. Outputs contain `TxOut`s for `Item`s of amount `3` and `3`
    /// 3. `TxIn` DRS matches `TxOut` DRS for `Item`s; Amount of `Item`s spent does not match    
    fn test_tx_drs_items_only_failure_amount_mismatch() {
        test_tx_drs_common(
            &[
                (3, Some("genesis_hash_1"), None),
                (2, Some("genesis_hash_2"), None),
            ],
            &[(3, Some("genesis_hash_1")), (3, Some("genesis_hash_2"))],
            false,
        );
    }

    #[test]
    /// ### Test Case 4
    ///
    ///  - *Items only*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Item`s of amount `3` and `2` with different `genesis_hash` values
    /// 2. Outputs contain `TxOut`s for `Item`s of amount `3` and `2`
    /// 3. `TxIn` DRS does not match `TxOut` DRS for `Item`s; Amount of `Item`s spent matches     
    fn test_tx_drs_items_only_failure_drs_mismatch() {
        test_tx_drs_common(
            &[
                (3, Some("genesis_hash_1"), None),
                (2, Some("genesis_hash_2"), None),
            ],
            &[
                (3, Some("genesis_hash_1")),
                (2, Some("invalid_genesis_hash")),
            ],
            false,
        );
    }

    #[test]
    /// ### Test Case 5
    ///
    ///  - *Items and Tokens*
    /// -  *Success*
    ///
    /// 1. Inputs contain two `TxIn`s for `Item`s of amount `3` and `Token`s of amount `2`
    /// 2. Outputs contain `TxOut`s for `Item`s of amount `3` and `Token`s of amount `2`
    /// 3. `TxIn` DRS matches `TxOut` DRS for `Item`s; Amount of `Item`s and `Token`s spent matches      
    fn test_tx_drs_items_and_tokens_success() {
        test_tx_drs_common(
            &[(3, Some("genesis_hash"), None), (2, None, None)],
            &[(3, Some("genesis_hash")), (2, None)],
            true,
        );
    }

    #[test]
    /// ### Test Case 6
    ///
    ///  - *Items and Tokens*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Item`s of amount `3` and `Token`s of amount `2`
    /// 2. Outputs contain `TxOut`s for `Item`s of amount `2` and `Token`s of amount `2`
    /// 3. `TxIn` DRS matches `TxOut` DRS for `Item`s; Amount of `Item`s spent does not match      
    fn test_tx_drs_items_and_tokens_failure_amount_mismatch() {
        test_tx_drs_common(
            &[(3, Some("genesis_hash"), None), (2, None, None)],
            &[(2, Some("genesis_hash")), (2, None)],
            false,
        );
    }

    #[test]
    /// ### Test Case 7
    ///
    ///  - *Items and Tokens*
    /// -  *Failure*
    ///
    /// 1. Inputs contain two `TxIn`s for `Item`s of amount `3` and `Token`s of amount `2`
    /// 2. Outputs contain `TxOut`s for `Item`s of amount `1` and Tokens of amount `1`
    /// 3. `TxIn` DRS does not match `TxOut` DRS for `Item`s; Amount of `Item`s and `Token`s spent does not match;
    /// Metadata does not match                
    fn test_tx_drs_items_and_tokens_failure_amount_and_drs_mismatch() {
        let test_metadata: Option<String> = Some(
            "{\"name\":\"test\",\"description\":\"test\",\"image\":\"test\",\"url\":\"test\"}"
                .to_string(),
        );

        test_tx_drs_common(
            &[
                (3, Some("genesis_hash"), test_metadata.clone()),
                (2, None, test_metadata),
            ],
            &[(1, Some("invalid_genesis_hash")), (1, None)],
            false,
        );
    }

    /// Test transaction validation with multiple different DRS
    /// configurations for `TxIn` and `TxOut` values
    fn test_tx_drs_common(
        inputs: &[(u64, Option<&str>, Option<String>)],
        outputs: &[(u64, Option<&str>)],
        expected_result: bool,
    ) {
        ///
        /// Arrange
        ///
        let (utxo, tx) = generate_tx_with_ins_and_outs_assets(inputs, outputs);

        ///
        /// Act
        ///
        let actual_result = tx_is_valid(&tx, 100, |v| utxo.get(v));

        ///
        /// Assert
        ///
        assert_eq!(actual_result, expected_result);
    }

    #[test]
    /// Checks that incorrect member interpret scripts are validated as such
    fn test_fail_interpret_valid() {
        let (_pk, sk) = sign::gen_keypair().unwrap();
        let (pk, _sk) = sign::gen_keypair().unwrap();
        let t_hash = TxHash::placeholder();
        let signature = sign::sign_detached(t_hash.as_ref(), &sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new_from_hash(t_hash, 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert_eq!(tx_ins[0].clone().script_signature.interpret_full(), Err(ScriptError::LastEntryIsZero));
    }

    #[test]
    /// Checks that interpret scripts are validated as such
    fn test_pass_interpret_valid() {
        let (pk, sk) = sign::gen_keypair().unwrap();
        let t_hash = TxHash::placeholder();
        let signature = sign::sign_detached(hex::encode(t_hash.as_ref()).as_bytes(), &sk);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new_from_hash(t_hash, 0),
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert_eq!(tx_ins[0].clone().script_signature.interpret_full(), Ok(()));
    }
}
