use crate::constants::*;
use crate::crypto::{sha3_256, sign_ed25519};
use crate::crypto::sign_ed25519::{self as sign, sign_detached, PublicKey, SecretKey};
use crate::primitives::asset::Asset;
use crate::primitives::druid::{DdeValues, DruidExpectation};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::script::{OpCodes, ScriptEntry, StackEntry};
use std::collections::BTreeMap;
use std::convert::TryInto;
use tracing::debug;
use crate::primitives::address::{AnyAddress, P2PKHAddress};
use crate::primitives::format;

pub struct ReceiverInfo {
    pub address: AnyAddress,
    pub asset: Asset,
}

/// Builds a P2SH address
///
/// ### Arguments
///
/// * `script` - Script to build address for
pub fn construct_p2sh_address(script: &Script) -> String {
    let bytes = match bincode::serde::encode_to_vec(script, bincode::config::legacy()) {
        Ok(bytes) => bytes,
        Err(_) => vec![],
    };
    let mut addr = hex::encode(sha3_256::digest(&bytes));
    addr.insert(ZERO, P2SH_PREPEND as char);
    addr.truncate(STANDARD_ADDRESS_LENGTH);
    addr

    /*let script_signable_string = script.stack.iter()
        .map(|entry| match entry {
            StackEntry::Op(op) => op.to_string(),
            StackEntry::Signature(sig) => hex::encode(sig.as_ref()),
            StackEntry::PubKey(pubkey) => hex::encode(pubkey.as_ref()),
            StackEntry::Bytes(bytes) => hex::encode(bytes),
            StackEntry::Num(n) => n.to_string(),
        })
        .collect::<Vec<String>>()
        .join("\n");

    hex::encode(sha3_256::digest(script_signable_string.as_bytes()))*/
}

/// Builds an address from a public key
///
/// ### Arguments
///
/// * `pub_key` - A public key to build an address from
#[deprecated = "Use P2PKHAddress::from_pubkey"]
pub fn construct_address(pub_key: &PublicKey) -> String {
    hex::encode(sha3_256::digest(pub_key.as_ref()))
}

/// Constructs signable string for OutPoint
///
/// ### Arguments
///
/// * `out_point`   - OutPoint value
pub fn get_out_point_signable_string(out_point: &OutPoint) -> String {
    format!("{}-{}", out_point.n, out_point.t_hash)
}

/// Constructs signable hash for a TxIn
///
/// ### Arguments
///
/// * `previous_out`   - Previous transaction used as input
pub fn construct_tx_in_signable_hash(previous_out: &OutPoint) -> String {
    hex::encode(sha3_256::digest(
        get_out_point_signable_string(previous_out).as_bytes(),
    ))
}

/// Constructs signable string for an Asset
///
/// ### Arguments
///
/// * `asset`   - Asset to sign
pub fn get_asset_signable_string(asset: &Asset) -> String {
    match asset {
        Asset::Token(token_amount) => format!("Token:{}", token_amount.0),
        Asset::Item(item) => format!("Item:{}", item.amount),
    }
}

/// Constructs signable asset hash for a TxIn
///
/// ### Arguments
///
/// * `asset`   - Asset to sign
pub fn construct_tx_in_signable_asset_hash(asset: &Asset) -> String {
    hex::encode(sha3_256::digest(
        get_asset_signable_string(asset).as_bytes(),
    ))
}

/// Constructs signable string from both TxIns and TxOuts
///
/// ### Arguments
///
/// * `tx_in`   - TxIn values
/// * `tx_out`  - TxOut values
pub fn construct_tx_in_out_signable_hash(previous_out: &OutPoint, tx_out: &[TxOut]) -> String {
    let mut signable_list = tx_out
        .iter()
        .map(|tx| {
            debug!("txout: {:?}", tx);
            serde_json::to_string(tx).unwrap()
        })
        .collect::<Vec<String>>();

    let tx_in_value = serde_json::to_string(&previous_out).unwrap();

    signable_list.push(tx_in_value);
    let signable = signable_list.join("");
    debug!("Formatted string for signing: {signable}");
    debug!(
        "Hash: {:?}",
        hex::encode(sha3_256::digest(signable.as_bytes()))
    );

    hex::encode(sha3_256::digest(signable.as_bytes()))
}

/// Constructs signable string for a StackEntry
///
/// ### Arguments
///
/// * `entry`   - StackEntry to obtain signable string for
#[deprecated = "This should only be used for v6 scripts; it will be removed in the future"]
fn get_stack_entry_signable_string(entry: &StackEntry) -> String {
    match entry {
        StackEntry::Op(op) => format!("Op:{op}"),
        StackEntry::Signature(signature) => {
            format!("Signature:{}", hex::encode(signature.as_ref()))
        }
        StackEntry::PubKey(pub_key) => format!("PubKey:{}", hex::encode(pub_key.as_ref())),
        StackEntry::Num(num) => format!("Num:{num}"),
        StackEntry::Bytes(bytes) => format!("Bytes:{}", hex::encode(bytes)),
    }
}

/// Constructs signable string for Script stack
///
/// ### Arguments
///
/// * `stack`   - StackEntry vector
#[deprecated = "This should only be used for v6 scripts; it will be removed in the future"]
fn get_script_signable_string(stack: &[StackEntry]) -> String {
    stack
        .iter()
        .map(get_stack_entry_signable_string)
        .collect::<Vec<String>>()
        .join("-")
}

/// Constructs signable string for TxIn
///
/// ### Arguments
///
/// * `tx_in`   - TxIn value
fn get_tx_in_address_signable_string(
    tx_version: TxVersion,
    tx_in: (usize, &TxIn),
    tx_outs: &[TxOut],
) -> String {
    let (_tx_in_index, tx_in) = tx_in;

    match tx_version {
        TxVersion::V6 => match tx_in {
            TxIn::Coinbase(CoinbaseTxIn { block_number }) =>
                format!("null-Num:{}", block_number),
            TxIn::Create(CreateTxIn { block_number, asset_hash, signature, public_key }) =>
                format!("null-Op:OP_CREATE-Num:{}-Op:OP_DROP-Bytes:{}-Signature:{}-PubKey:{}-Op:OP_CHECKSIG",
                        block_number,
                        hex::encode(asset_hash),
                        hex::encode(signature.as_ref()),
                        hex::encode(public_key.as_ref())),
            TxIn::P2PKH(p2pkh) =>
                format!("{}-Bytes:{}-Signature:{}-PubKey:{}-Op:OP_DUP-Op:OP_HASH256-Bytes:{}-Op:OP_EQUALVERIFY-Op:OP_CHECKSIG",
                        get_out_point_signable_string(&p2pkh.previous_out),
                        format::v6::find_v6_p2pkh_check_data(p2pkh, tx_outs).unwrap(),
                        hex::encode(p2pkh.signature.as_ref()),
                        hex::encode(p2pkh.public_key.as_ref()),
                        hex::encode(sha3_256::digest(p2pkh.public_key.as_ref()))),
        }
    }
}

/// Constructs address for a TxIn collection
///
/// ### Arguments
///
/// * `tx`   - The transaction
pub fn construct_tx_ins_address(
    tx_version: TxVersion,
    tx_ins: &[TxIn],
    tx_outs: &[TxOut],
) -> String {
    let signable_tx_ins = tx_ins.iter()
        .enumerate()
        .map(|tx_in| get_tx_in_address_signable_string(tx_version, tx_in, tx_outs))
        .collect::<Vec<String>>()
        .join("-");
    hex::encode(sha3_256::digest(signable_tx_ins.as_bytes()))
}

/// Get all the hash to remove from UTXO set for the utxo_entries
///
/// ### Arguments
///
/// * `utxo_entries` - The entries to to provide an update for.
pub fn get_inputs_previous_out_point<'a>(
    utxo_entries: impl Iterator<Item = &'a Transaction>,
) -> impl Iterator<Item = &'a OutPoint> {
    utxo_entries
        .filter(|tx| !tx.is_create_tx())
        .flat_map(|val| val.inputs.iter())
        .map(|input| input.find_previous_out().unwrap())
}

/// Get all the OutPoint and Transaction from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_with_out_point<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)>,
) -> impl Iterator<Item = (OutPoint, &'a Transaction)> {
    txs.map(|(hash, tx)| (hash, tx, &tx.outputs))
        .flat_map(|(hash, tx, outs)| outs.iter().enumerate().map(move |(idx, _)| (hash, idx, tx)))
        .map(|(hash, idx, tx)| (OutPoint::new_from_hash(hash.parse().unwrap(), idx as u32), tx))
}

/// Get all the OutPoint and Transaction from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_with_out_point_cloned<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)> + 'a,
) -> impl Iterator<Item = (OutPoint, Transaction)> + 'a {
    get_tx_with_out_point(txs).map(|(h, tx)| (h, tx.clone()))
}

/// Get all the OutPoint and TxOut from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_out_with_out_point<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)>,
) -> impl Iterator<Item = (OutPoint, &'a TxOut)> {
    txs.map(|(hash, tx)| (hash, tx.outputs.iter()))
        .flat_map(|(hash, outs)| outs.enumerate().map(move |(idx, txo)| (hash, idx, txo)))
        .map(|(hash, idx, txo)| (OutPoint::new_from_hash(hash.parse().unwrap(), idx as u32), txo))
}

/// Get all fee outputs from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_fees_with_out_point<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)>,
) -> impl Iterator<Item = (OutPoint, &'a TxOut)> {
    txs.map(|(hash, tx)| (hash, tx.fees.iter()))
        .flat_map(|(hash, outs)| outs.enumerate().map(move |(idx, txo)| (hash, idx, txo)))
        .map(|(hash, idx, txo)| (OutPoint::new_from_hash(hash.parse().unwrap(), idx as u32), txo))
}

/// Get all fee outputs from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_fees_with_out_point_cloned<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)> + 'a,
) -> impl Iterator<Item = (OutPoint, TxOut)> + 'a {
    txs.map(|(hash, tx)| (hash, tx.fees.iter()))
        .flat_map(|(hash, outs)| outs.enumerate().map(move |(idx, txo)| (hash, idx, txo)))
        .map(|(hash, idx, txo)| (OutPoint::new_from_hash(hash.parse().unwrap(), idx as u32), txo.clone()))
}

/// Get all the OutPoint and TxOut from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_out_with_out_point_cloned<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)> + 'a,
) -> impl Iterator<Item = (OutPoint, TxOut)> + 'a {
    get_tx_out_with_out_point(txs).map(|(o, txo)| (o, txo.clone()))
}

/// Constructs the UTXO set for the current state of the blockchain
///
/// ### Arguments
///
/// * `current_utxo` - The current UTXO set to be updated.
pub fn update_utxo_set(current_utxo: &mut BTreeMap<OutPoint, Transaction>) {
    let value_set: Vec<OutPoint> = get_inputs_previous_out_point(current_utxo.values())
        .cloned()
        .collect();
    value_set.iter().for_each(move |t_hash| {
        current_utxo.remove(t_hash);
    });
}

/// Constructs a search-valid hash for a transaction to be added to the blockchain
///
/// ### Arguments
///
/// * `tx`  - Transaction to hash
pub fn construct_tx_hash(tx: &Transaction) -> String {
    let bytes = match tx.version {
        TxVersion::V6 => format::v6::serialize(tx)
            .expect("Failed to serialize v6 transaction!"),
    };
    let mut hash = hex::encode(sha3_256::digest(&bytes));
    hash.insert(ZERO, TX_PREPEND as char);
    hash.truncate(TX_HASH_LENGTH);
    hash
}

/// Constructs a valid TxIn for a new create asset transaction
///
/// ### Arguments
///
/// * `block_num`   - Block number
/// * `asset`       - Asset to create
/// * `public_key`  - Public key to sign with
/// * `secret_key`  - Corresponding private key
pub fn construct_create_tx_in(
    block_num: u64,
    asset: &Asset,
    public_key: PublicKey,
    secret_key: &SecretKey,
) -> Vec<TxIn> {
    let asset_hash = construct_tx_in_signable_asset_hash(asset);
    let signature = sign::sign_detached(asset_hash.as_bytes(), secret_key);

    vec![TxIn::Create(CreateTxIn {
        block_number: block_num,
        asset_hash: hex::decode(&asset_hash).unwrap(),
        public_key,
        signature,
    })]
}

/// Constructs a item data asset for use in accepting payments
/// TODO: On compute, figure out a way to ease flow of items without issue for users
///
/// ### Arguments
///
/// * `block_num`           - Block number
/// * `public_key`          - Public key for the output address
/// * `secret_key`          - Corresponding secret key for signing data
/// * `amount`              - Amount of item assets to create
pub fn construct_item_create_tx(
    block_num: u64,
    public_key: PublicKey,
    secret_key: &SecretKey,
    amount: u64,
    genesis_hash_spec: GenesisTxHashSpec,
    fee: Option<ReceiverInfo>,
    metadata: Option<String>,
) -> Transaction {
    let genesis_hash = genesis_hash_spec.get_genesis_hash()
        .map(|hash| hash.parse().expect(&hash)); // TODO: jrabil: This will always fail for GenesisTxHashSpec::Default
    let asset = Asset::item(amount, genesis_hash, metadata);
    let receiver_address = P2PKHAddress::from_pubkey(&public_key).wrap();

    let tx_ins = construct_create_tx_in(block_num, &asset, public_key, secret_key);
    let tx_out = TxOut::new_asset(receiver_address, asset, None);

    construct_tx_core(tx_ins, vec![tx_out], fee)
}

/// Constructs a transaction to pay a receiver
///
/// TODO: Check whether the `amount` is valid in the TxIns
/// TODO: Call this a charity tx or something, as a payment is an exchange of goods
///
/// ### Arguments
///
/// * `tx_ins`              - Input/s to pay from
/// * `receiver_address`    - Address to send to
/// * `drs_block_hash`      - Hash of the block containing the original DRS. Only for data trades
/// * `asset`               - Asset to send
/// * `locktime`            - Block height below which the payment is restricted. "0" means no locktime
pub fn construct_payment_tx(
    tx_ins: Vec<TxInConstructor>,
    receiver: ReceiverInfo,
    fee: Option<ReceiverInfo>,
    locktime: u64,
    key_material: &BTreeMap<OutPoint, (PublicKey, SecretKey)>
) -> Transaction {
    let tx_out = TxOut::new_asset(receiver.address, receiver.asset, Some(locktime));
    let tx_outs = vec![tx_out];
    let final_tx_ins = update_input_signatures(&tx_ins, &tx_outs, key_material);

    construct_tx_core(final_tx_ins, tx_outs, fee)
}

/// Constructs a transaction to burn tokens
///
/// ### Arguments
///
/// * `tx_ins`  - Input/s to pay from
// TODO: This seems kinda dumb, because there's no way to indicate where the change should go.
pub fn construct_burn_tx(
    tx_ins: Vec<TxInConstructor>,
    value: Asset,
    fee: Option<ReceiverInfo>,
    key_material: &BTreeMap<OutPoint, (PublicKey, SecretKey)>,
) -> Transaction {
    todo!();

    let tx_out = TxOut::new_asset(AnyAddress::Burn, value, None);
    let tx_outs = vec![tx_out];

    let final_tx_ins = update_input_signatures(&tx_ins, &tx_outs, key_material);

    construct_tx_core(final_tx_ins, tx_outs, fee)
}

/// Constructs a transaction to pay a receiver
/// If TxIn collection does not add up to the exact amount to pay,
/// payer will always need to provide a return payment in tx_outs,
/// otherwise the excess will be burnt and unusable.
///
/// TODO: Check whether the `amount` is valid in the TxIns
/// TODO: Call this a charity tx or something, as a payment is an exchange of goods
///
/// ### Arguments
///
/// * `tx_ins`     - Address/es to pay from
/// * `tx_outs`    - Address/es to send to
pub fn construct_tx_core(
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>,
    fee: Option<ReceiverInfo>
) -> Transaction {
    let fee_tx_out = match fee {
        Some(fee) => vec![TxOut::new_asset(fee.address, fee.asset, None)],
        None => vec![],
    };

    Transaction {
        inputs: tx_ins,
        outputs: tx_outs,
        fees: fee_tx_out,
        ..Default::default()
    }
}

/// Constructs a core item-based payment transaction
///
/// ### Arguments
///
/// * `from_address`    - Address receiving asset from
/// * `to_address`      - Address sending asset to
/// * `asset`           - Asset to send
/// * `tx_ins`          - TxIns for outgoing transaction
/// * `out`             - The TxOut for this send
/// * `druid`           - DRUID to match on
pub fn construct_rb_tx_core(
    tx_ins: Vec<TxInConstructor>,
    tx_outs: Vec<TxOut>,
    fee: Option<ReceiverInfo>,
    druid: String,
    druid_expectation: Vec<DruidExpectation>,
    key_material: &BTreeMap<OutPoint, (PublicKey, SecretKey)>
) -> Transaction {
    let tx_ins = update_input_signatures(&tx_ins, &tx_outs, key_material);

    let mut tx = construct_tx_core(tx_ins, tx_outs, fee);

    tx.druid_info = Some(DdeValues {
        druid,
        participants: 2,
        expectations: druid_expectation,
        genesis_hash: None,
    });

    tx
}

/// Builds `TxIn`s from the given `TxInConstructor`s.
/// 
/// ### Arguments
/// 
/// * `tx_ins`          - Inputs to the transaction
/// * `tx_outs`         - Outputs of the transaction
// TODO: rename this to something less confusing
pub fn update_input_signatures(tx_ins: &[TxInConstructor], tx_outs: &[TxOut], key_material: &BTreeMap<OutPoint, (PublicKey, SecretKey)>) -> Vec<TxIn> {
    tx_ins.iter()
        .map(|ctor| match *ctor {
            TxInConstructor::Coinbase { block_number } =>
                TxIn::Coinbase(CoinbaseTxIn {
                    block_number,
                }),
            TxInConstructor::Create { block_number, asset, public_key, secret_key } => {
                let asset_hash = construct_tx_in_signable_asset_hash(asset);

                TxIn::Create(CreateTxIn {
                    block_number,
                    asset_hash: hex::decode(&asset_hash).unwrap(),
                    public_key: public_key.clone(),
                    signature: sign_ed25519::sign_detached(asset_hash.as_bytes(), secret_key),
                })
            },
            TxInConstructor::P2PKH { previous_out, public_key, secret_key } => {
                let signable_hash = construct_tx_in_out_signable_hash(previous_out, tx_outs);

                TxIn::P2PKH(P2PKHTxIn {
                    previous_out: previous_out.clone(),
                    public_key: public_key.clone(),
                    signature: sign_ed25519::sign_detached(signable_hash.as_bytes(), secret_key),
                })
            },
        })
        .collect()
}

/// Constructs the "send" half of a item-based payment
/// transaction
///
/// ### Arguments
///
/// * `receiver_address`    - Own address to receive item to
/// * `amount`              - Amount of token to send
/// * `locktime`            - Block height to lock the current transaction to
pub fn construct_rb_payments_send_tx(
    tx_ins: Vec<TxInConstructor>,
    mut tx_outs: Vec<TxOut>,
    fee: Option<ReceiverInfo>,
    receiver: ReceiverInfo,
    locktime: u64,
    druid_info: DdeValues,
    key_material: &BTreeMap<OutPoint, (PublicKey, SecretKey)>
) -> Transaction {
    let out = TxOut::new_asset(receiver.address, receiver.asset, Some(locktime));
    tx_outs.push(out);
    construct_rb_tx_core(
        tx_ins,
        tx_outs,
        fee,
        druid_info.druid,
        druid_info.expectations,
        key_material,
    )
}

/// Constructs the "receive" half of a item-based payment
/// transaction
///
/// ### Arguments
///
/// * `tx_ins`              - Inputs to item data asset
/// * `sender_address`      - Address of sender
/// * `sender_send_addr`    - Input hash used by sender to send tokens
/// * `own_address`         - Own address to receive tokens to
/// * `amount`              - Number of tokens expected
/// * `locktime`            - Block height below which the payment item is restricted. "0" means no locktime
/// * `druid`               - The matching DRUID value
pub fn construct_rb_receive_payment_tx(
    tx_ins: Vec<TxInConstructor>,
    mut tx_outs: Vec<TxOut>,
    fee: Option<ReceiverInfo>,
    sender_address: AnyAddress,
    locktime: u64,
    druid_info: DdeValues,
    key_material: &BTreeMap<OutPoint, (PublicKey, SecretKey)>
) -> Transaction {
    let genesis_hash = druid_info.genesis_hash.as_ref()
        .map(|hash| hash.parse().expect(&hash));
    let out = TxOut::new_asset(sender_address, Asset::item(1, genesis_hash, None), Some(locktime));
    tx_outs.push(out);
    construct_rb_tx_core(
        tx_ins,
        tx_outs,
        fee,
        druid_info.druid,
        druid_info.expectations,
        key_material,
    )
}

/// Constructs a set of TxIns for a payment
///
/// ### Arguments
///
/// * `tx_values`   - Series of values required for TxIn construction
#[deprecated = "This is no longer necessary"]
pub fn construct_payment_tx_ins(tx_values: Vec<TxConstructor>) -> Vec<TxIn> {
    todo!()
    /*let mut tx_ins = Vec::new();

    for entry in tx_values {
        let signable_prev_out = TxIn {
            previous_out: Some(entry.previous_out),
            script_signature: Script::new(),
        };
        let previous_out = signable_prev_out.previous_out;
        let script_signature = Script::new();

        tx_ins.push(TxIn {
            previous_out,
            script_signature,
        });
    }

    tx_ins*/
}

/// Constructs a dual double entry tx
///
/// ### Arguments
///
/// * `druid`                           - DRUID value to match with the other party
/// * `tx_ins`                          - Addresses to pay from
/// * `send_asset_drs_hash`             - Hash of the block containing the DRS for the sent asset. Only applicable to data trades
/// * `participants`                    - Participants in trade
/// * `(send_address, receive_address)` - Send and receive addresses as a tuple
/// * `(send_asset, receive_asset)`     - Send and receive assets as a tuple
pub fn construct_dde_tx(
    druid_info: DdeValues,
    tx_ins: Vec<TxInConstructor>,
    tx_outs: Vec<TxOut>,
    fee: Option<ReceiverInfo>,
    key_material: &BTreeMap<OutPoint, (PublicKey, SecretKey)>
) -> Transaction {
    let tx_ins = update_input_signatures(&tx_ins, &tx_outs, key_material);

    let mut tx = construct_tx_core(tx_ins, tx_outs, fee);

    tx.druid_info = Some(druid_info);

    tx
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;
    use super::*;
    use crate::crypto::sign_ed25519::{self as sign, Signature};
    use crate::primitives::address::P2PKHAddress;
    use crate::primitives::asset::{AssetValues, ItemAsset, TokenAmount};
    use crate::script::{OpCodes, ScriptError};
    use crate::utils::Placeholder;
    use crate::utils::IntoArray;
    use crate::utils::script_utils::tx_outs_are_valid;

    fn test_construct_valid_inputs() -> (Vec<TxInConstructor<'static>>, String, BTreeMap<OutPoint, (PublicKey, SecretKey)>) {
        static KEYPAIR: Lazy<(PublicKey, SecretKey)> = Lazy::new(|| sign::gen_test_keypair(0).unwrap());
        static PREV_OUT : Lazy<OutPoint> = Lazy::new(|| OutPoint::new_from_hash(TxHash::placeholder(), 0));

        let (pk, sk) = &*KEYPAIR;
        let prev_out = &*PREV_OUT;
        let drs_block_hash = hex::encode(&[1, 2, 3, 4, 5, 6]);

        let key_material = BTreeMap::from([
            ( prev_out.clone(), (pk.clone(), sk.clone()) ),
        ]);

        let tx_ins = vec![TxInConstructor::P2PKH {
            previous_out: prev_out,
            public_key: pk,
            secret_key: sk,
        }];

        (tx_ins, drs_block_hash, key_material)
    }

    #[test]
    fn test_construct_a_valid_p2sh_tx() {
        todo!();

        /*let token_amount = TokenAmount(400000);
        let (tx_ins, _drs_block_hash, key_material) = test_construct_valid_inputs();
        let script = Script::build(&[
            ScriptEntry::Int(10),
            ScriptEntry::Op(OpCodes::OP_DROP),
            ScriptEntry::Int(1),
        ]);

        let p2sh_tx = construct_p2sh_tx(tx_ins, None, &script, Asset::Token(token_amount), 0, &key_material);

        let spending_tx_hash = construct_tx_hash(&p2sh_tx);

        let tx_const = TxConstructor {
            previous_out: OutPoint::new_from_hash(spending_tx_hash.parse().unwrap(), 0),
            signatures: vec![],
            pub_keys: vec![],
        };

        let redeeming_tx_ins = construct_p2sh_redeem_tx_ins(tx_const, script.clone());
        let redeeming_tx = construct_payment_tx(
            redeeming_tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(token_amount),
            },
            None,
            0,
            &key_material
        );
        let p2sh_script_pub_key = p2sh_tx.outputs[0].script_public_key.as_ref().unwrap();

        assert_eq!(Asset::Token(token_amount), p2sh_tx.outputs[0].value);
        assert_eq!(p2sh_script_pub_key.as_bytes()[0], P2SH_PREPEND);
        assert_eq!(p2sh_script_pub_key.len(), STANDARD_ADDRESS_LENGTH);
        assert!(tx_has_valid_p2sh_script(
            &redeeming_tx.inputs[0].script_signature,
            p2sh_tx.outputs[0].script_public_key.as_ref().unwrap()
        ));*/

        // TODO: Add assertion for full tx validity
    }

    #[test]
    fn test_construct_a_valid_burn_tx() {
        let token_amount = TokenAmount(400000);
        let (tx_ins, _drs_block_hash, key_material) = test_construct_valid_inputs();

        let burn_tx = construct_burn_tx(tx_ins, Asset::Token(token_amount), None, &key_material);
        let spending_tx_hash = construct_tx_hash(&burn_tx);

        /*let tx_const = TxConstructor {
            previous_out: OutPoint::new_from_hash(spending_tx_hash.parse().unwrap(), 0),
            signatures: vec![],
            pub_keys: vec![],
        };

        let script = Script::build(&[ScriptEntry::Op(OpCodes::OP_BURN)]);

        let redeeming_tx_ins = construct_p2sh_redeem_tx_ins(tx_const, script);
        let redeeming_tx = construct_payment_tx(
            redeeming_tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(token_amount),
            },
            None,
            0,
            &key_material
        );
        let burn_script_pub_key = burn_tx.outputs[0].script_public_key.as_ref().unwrap();
        debug!("{:?}", burn_script_pub_key);

        assert_eq!(burn_script_pub_key.as_bytes()[0], P2SH_PREPEND);
        assert_eq!(burn_script_pub_key.len(), STANDARD_ADDRESS_LENGTH);
        assert_eq!(redeeming_tx.inputs[0].script_signature.interpret_full(), Err(ScriptError::Burn));
        assert!(!tx_has_valid_p2sh_script(
            &redeeming_tx.inputs[0].script_signature,
            burn_tx.outputs[0].script_public_key.as_ref().unwrap()
        ));*/

        // TODO: Add assertion for full tx validity
    }

    #[test]
    fn test_construct_a_valid_payment_tx() {
        let (tx_ins, _drs_block_hash, key_material) = test_construct_valid_inputs();

        let token_amount = TokenAmount(400000);
        let payment_tx = construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(token_amount),
            },
            None,
            0,
            &key_material
        );
        assert_eq!(Asset::Token(token_amount), payment_tx.outputs[0].value);
        assert_eq!(
            payment_tx.outputs[0].script_public_key,
            hex::encode(vec![0u8; 32]).parse().unwrap(),
        );
    }

    #[test]
    /// Creates a valid payment transaction including fees
    fn test_construct_valid_payment_tx_with_fees() {
        let (tx_ins, _drs_block_hash, key_material) = test_construct_valid_inputs();

        let token_amount = TokenAmount(400000);
        let fee_amount = TokenAmount(1000);
        let payment_tx = construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(token_amount),
            },
            Some(ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(fee_amount),
            }),
            0,
            &key_material
        );
        assert_eq!(Asset::Token(token_amount), payment_tx.outputs[0].value);
        assert_eq!(Asset::Token(fee_amount), payment_tx.fees[0].value);
    }

    #[test]
    /// Creates a valid payment transaction including fees
    fn test_token_onspend_with_fees() {
        let tokens = TokenAmount(400000);
        let fees = TokenAmount(1000);

        let (tx_ins, _drs_block_hash, key_material) = test_construct_valid_inputs();

        let payment_tx_valid = construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(tokens),
            },
            Some(ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(fees),
            }),
            0,
            &key_material
        );

        let tx_ins_spent = AssetValues::new(tokens + fees, BTreeMap::new());

        assert!(tx_outs_are_valid(
            &payment_tx_valid.outputs,
            &payment_tx_valid.fees,
            tx_ins_spent
        ));
    }

    #[test]
    /// Checks the validity of on-spend for items with fees
    fn test_item_onspend_with_fees() {
        let fees = TokenAmount(1000);

        let (tx_ins, _drs_block_hash, key_material) = test_construct_valid_inputs();

        let drs_tx_hash = TxHash::placeholder();
        let item_asset_valid = ItemAsset::new(1000, Some(drs_tx_hash.clone()), None);

        let payment_tx_valid = construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Item(item_asset_valid),
            },
            Some(ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(fees),
            }),
            0,
            &key_material
        );

        let btree = BTreeMap::from([
            (drs_tx_hash.clone(), 1000),
        ]);
        let tx_ins_spent = AssetValues::new(fees, btree);

        assert!(tx_outs_are_valid(
            &payment_tx_valid.outputs,
            &payment_tx_valid.fees,
            tx_ins_spent
        ));
    }

    #[test]
    /// Checks the validity of the metadata on-spend for items
    fn test_item_onspend_metadata() {
        let (tx_ins, _drs_block_hash, key_material) = test_construct_valid_inputs();

        let genesis_hash = TxHash::placeholder();
        let item_asset_valid = ItemAsset::new(1000, Some(genesis_hash.clone()), None);

        let payment_tx_valid = construct_payment_tx(
            tx_ins,
            ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Item(item_asset_valid),
            },
            None,
            0,
            &key_material
        );

        let btree = BTreeMap::from([
            ( genesis_hash.clone(), 1000 ),
        ]);
        let tx_ins_spent = AssetValues::new(TokenAmount(0), btree);

        assert!(tx_outs_are_valid(
            &payment_tx_valid.outputs,
            &[],
            tx_ins_spent
        ));
    }

    #[test]
    // Creates a valid UTXO set
    fn test_construct_valid_utxo_set() {
        let (pk, sk) = sign::gen_test_keypair(0).unwrap();

        let t_hash_1 = TxHash::placeholder_indexed(1);
        let prev_out = OutPoint::new_from_hash(t_hash_1, 0);

        let key_material_1 = BTreeMap::from([
            (prev_out.clone(), (pk.clone(), sk.clone())),
        ]);

        let token_amount = TokenAmount(400000);
        let tx_ins_1 = vec![TxInConstructor::P2PKH {
            previous_out: &prev_out,
            public_key: &pk,
            secret_key: &sk,
        }];
        let payment_tx_1 = construct_payment_tx(
            tx_ins_1,
            ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(token_amount),
            },
            None,
            0,
            &key_material_1,
        );
        let tx_1_hash = construct_tx_hash(&payment_tx_1);
        let tx_1_out_p = OutPoint::new_from_hash(tx_1_hash.parse().unwrap(), 0);

        // Second tx referencing first
        let key_material_2 = BTreeMap::from([
            (tx_1_out_p.clone(), (pk.clone(), sk.clone())),
        ]);

        let tx_ins_2 = vec![TxInConstructor::P2PKH {
            previous_out: &tx_1_out_p,
            public_key: &pk,
            secret_key: &sk,
        }];
        let payment_tx_2 = construct_payment_tx(
            tx_ins_2,
            ReceiverInfo {
                address: hex::encode(&[0u8; 32]).parse().unwrap(),
                asset: Asset::Token(token_amount),
            },
            None,
            0,
            &key_material_2,
        );

        let tx_2_hash = construct_tx_hash(&payment_tx_2);
        let tx_2_out_p = OutPoint::new_from_hash(tx_2_hash.parse().unwrap(), 0);

        // BTreemap
        let mut btree = BTreeMap::new();
        btree.insert(tx_1_out_p, payment_tx_1);
        btree.insert(tx_2_out_p.clone(), payment_tx_2);

        update_utxo_set(&mut btree);

        // Check that only one entry remains
        assert_eq!(btree.len(), 1);
        assert_ne!(btree.get(&tx_2_out_p), None);
    }

    #[test]
    // Creates a valid DDE transaction
    fn test_construct_a_valid_dde_tx() {
        let (tx_ins, _drs_block_hash, key_material) = test_construct_valid_inputs();
        let prev_out = OutPoint::new_from_hash(TxHash::placeholder(), 0);

        let to_address = AnyAddress::P2PKH(P2PKHAddress::placeholder());
        let data = Asset::Item(ItemAsset {
            metadata: Some("hello".to_string()),
            amount: 1,
            genesis_hash: None,
        });

        let tx_outs = vec![TxOut::new_asset(to_address, data.clone(), None)];

        let signed_tx_ins = update_input_signatures(&tx_ins, &tx_outs, &key_material);
        let from_addr = construct_tx_ins_address(TxVersion::V6, &signed_tx_ins, &tx_outs);

        // DDE params
        let druid = hex::encode(vec![1, 2, 3, 4, 5]);
        let participants = 2;
        let expects = vec![DruidExpectation {
            from: from_addr,
            to: to_address.to_string(),
            asset: data.clone(),
        }];

        // Actual DDE
        let druid_info = DdeValues {
            druid: druid.clone(),
            participants,
            expectations: expects.clone(),
            genesis_hash: None,
        };
        let dde = construct_dde_tx(druid_info, tx_ins, tx_outs, None, &key_material);

        assert_eq!(dde.druid_info.clone().unwrap().druid, druid);
        assert_eq!(dde.outputs[0].clone().value, data);
        assert_eq!(dde.druid_info.unwrap().participants, participants);
    }

    #[test]
    // Creates a valid item based tx pair
    fn test_construct_a_valid_item_tx_pair() {
        // Arrange
        //
        let amount = TokenAmount(33);
        let payment = TokenAmount(11);
        let druid = "VALUE".to_owned();

        let from_addr = construct_tx_ins_address(TxVersion::V6, &[], &[]);

        let alice_addr = P2PKHAddress::placeholder_indexed(0).wrap();
        let bob_addr = P2PKHAddress::placeholder_indexed(1).wrap();

        let sender_address_excess = P2PKHAddress::placeholder_indexed(2).wrap();

        let (pk, sk) = sign::gen_test_keypair(0).unwrap();
        let mut key_material = BTreeMap::new();

        let genesis_hash = TxHash::placeholder_indexed(0);

        // Act
        //
        let send_tx = {
            let tx_ins = vec![];
            key_material.insert(OutPoint::placeholder(), (pk, sk));

            let excess_tx_out =
                TxOut::new_token_amount(sender_address_excess, amount - payment, None);

            let expectation = DruidExpectation {
                from: from_addr.clone(),
                to: alice_addr.to_string(),
                asset: Asset::item(1, Some(genesis_hash.clone()), None),
            };

            let mut tx = construct_rb_payments_send_tx(
                tx_ins,
                Vec::new(),
                None,
                ReceiverInfo {
                    address: bob_addr.clone(),
                    asset: Asset::Token(payment),
                },
                0,
                DdeValues {
                    druid: druid.clone(),
                    participants: 2,
                    expectations: vec![expectation],
                    genesis_hash: None,
                },
                &key_material,
            );

            tx.outputs.push(excess_tx_out);

            tx
        };

        let recv_tx = {
            let tx_ins = vec![];
            let expectation = DruidExpectation {
                from: from_addr,
                to: bob_addr.to_string(),
                asset: Asset::Token(payment),
            };

            let druid_info = DdeValues {
                druid: druid.clone(),
                participants: 2,
                expectations: vec![expectation],
                genesis_hash: Some(genesis_hash.to_string()),
            };

            // create the sender that match the receiver.
            construct_rb_receive_payment_tx(tx_ins, Vec::new(), None, alice_addr, 0, druid_info, &key_material)
        };

        // Assert
        assert_eq!(
            send_tx
                .druid_info
                .as_ref()
                .map(|v| (&v.druid, v.participants)),
            Some((&druid, 2))
        );
        assert_eq!(
            recv_tx
                .druid_info
                .as_ref()
                .map(|v| (&v.druid, v.participants)),
            Some((&druid, 2))
        );
    }

    #[test]
    // Test valid address construction; should correlate with test on wallet
    fn test_construct_valid_addresses() {
        //
        // Arrange
        //
        let pub_keys = [
            "5371832122a8e804fa3520ec6861c3fa554a7f6fb617e6f0768452090207e07c",
            "6e86cc1fc5efbe64c2690efbb966b9fe1957facc497dce311981c68dac88e08c",
            "8b835e00c57ebff6637ec32276f2c6c0df71129c8f0860131a78a4692a0b59dc",
        ]
        .iter()
        .map(|v| hex::decode(v).unwrap())
        .map(|v| PublicKey::from_slice(&v).unwrap())
        .collect::<Vec<PublicKey>>();

        //
        // Act
        //
        let actual_pub_addresses: Vec<String> = pub_keys
            .iter()
            .map(construct_address)
            .collect();

        //
        // Assert
        //
        let expected_pub_addresses = vec![
            "5423e6bd848e0ce5cd794e55235c23138d8833633cd2d7de7f4a10935178457b",
            "77516e2d91606250e625546f86702510d2e893e4a27edfc932fdba03c955cc1b",
            "4cfd64a6692021fc417368a866d33d94e1c806747f61ac85e0b3935e7d5ed925",
        ];
        assert_eq!(actual_pub_addresses, expected_pub_addresses);
    }

    #[test]
    // Test TxIn signable hash construction; should correlate with test on wallet
    fn test_construct_valid_tx_in_signable_hash() {
        //
        // Arrange
        //
        let out_points = vec![
            OutPoint::placeholder_indexed(0),
            OutPoint::placeholder_indexed(1),
            OutPoint::placeholder_indexed(2),
        ];

        //
        // Act
        //
        let actual: Vec<String> = out_points
            .iter()
            .map(construct_tx_in_signable_hash)
            .collect();

        let expected: Vec<String> = vec![
            "08b4e1d78424bfa8dffffa499142b8e9f1edc4db4ec645d2fd2a60be2e8b3d9c".to_owned(),
            "7e335ddf926a4fa5c7817df622858226e68b929cead312e446df16e93108125c".to_owned(),
            "47dc4464616705a240fd94cd88991b2c2446d9e859162a2f900c4036ff85dac3".to_owned(),
        ];

        //
        // Assert
        //
        assert_eq!(actual, expected);
    }

    #[test]
    // Test TxIn signable asset hash construction; should correlate with test on wallet
    fn test_construct_valid_tx_in_signable_asset_hash() {
        //
        // Arrange
        //
        let assets = vec![Asset::token_u64(1), Asset::item(1, None, None)];

        //
        // Act
        //
        let actual: Vec<String> = assets
            .iter()
            .map(construct_tx_in_signable_asset_hash)
            .collect();

        let expected: Vec<String> = vec![
            "a5b2f5e8dcf824aee45b81294ff8049b680285b976cc6c8fa45eb070acfc5974".to_owned(),
            "cb8f6cba3a62cfb7cd14245f19509b800da3dd446b6d902290efbcc91b3cee0d".to_owned(),
        ];

        //
        // Assert
        //
        assert_eq!(actual, expected);
    }

    #[test]
    // Test valid TxIn address construction; should correlate with test on wallet
    fn test_construct_valid_tx_ins_address() {
        //
        // Arrange
        //
        const TX_IN_COUNT : usize = 3;

        let tx_outs = [];

        let tx_version = TxVersion::V6;

        let secret_keys = [
            "3053020101300506032b65700422042048dda5bbe9171a6656206ec56c595c5834b6cf38c5fe71bcb44fe43833aee9dfa1230321004a423a99c7d946e88da185f8f400e41cee388a95ecedc8603136de50aea12182",
            "3053020101300506032b657004220420b875632ccf606eef2397124e6c2febf24e91a89b43c6bf762c8e9ea61a48e9a9a1230321002a698271b680fd389ca2dc4823a8084065b2554caf0753b5ddc57a750564b1d4",
            "3053020101300506032b65700422042087ac5d1ddfa64329d8548b34c25ee5edea790e1311eb55467461114c31f1a011a1230321003549f82095030b2ca9577c828363f0fdbd92d9a131f698536e6b306cdad3f26e",
        ].map(|sk| SecretKey::from_slice(&hex::decode(sk).expect(sk)).expect(sk));

        let pub_keys = secret_keys.each_ref().map(SecretKey::get_public_key);

        let signatures = [
            "36f303bb3f677ac36829e265dcef8e4ed9c83d8e974edfafdb487ad5e3a763055e66ecd5cbb40a1e3d26efe5012b39fae18b87e0a0fc8028d35e277ca0b7f20f",
            "9c0ef4c0a453f41c3887b29c32a057956adcc4104e226a5f8d601b7dd9f3c6889a963e255440e6716c36d3e865c30c54fa4b3145c83053d6d8461e7f0f872b08",
            "c19533e0b6d7d355f11c7f3911e05f11d9b6d50a571496e71eae223d86f42e67d69574f6313ba1c2976bbc82452caca467e74108d5cda371574746d677620000",
        ].map(|sig| Signature::from_slice(&hex::decode(sig).expect(sig)).expect(sig));

        let signable_data = [
            "2343882840e27740d97be23e8940390af6c8d97d5878bdecd6462520b981eeb7",
            "9081d463757aa7ed5213e734ea13ff66db84ba8ca70dee97e2c4ec008759d8f2",
            "45edc12b9c1457b82c499d90e702e29fc66474e2b8ca302bd3eb61dd2b7eb4b7",
        ];

        let previous_out_points = [
            OutPoint::placeholder_indexed(0),
            OutPoint::placeholder_indexed(1),
            OutPoint::placeholder_indexed(2),
        ];

        let tx_in_address_signable_strings = [
            "0-g48dda5bbe9171a6656206ec56c595c5-Bytes:2343882840e27740d97be23e8940390af6c8d97d5878bdecd6462520b981eeb7-Signature:36f303bb3f677ac36829e265dcef8e4ed9c83d8e974edfafdb487ad5e3a763055e66ecd5cbb40a1e3d26efe5012b39fae18b87e0a0fc8028d35e277ca0b7f20f-PubKey:4a423a99c7d946e88da185f8f400e41cee388a95ecedc8603136de50aea12182-Op:OP_DUP-Op:OP_HASH256-Bytes:09e184b463e5e8d4efaa3ff510f18421c7e50fe42fe4da7b54532ca206f339bb-Op:OP_EQUALVERIFY-Op:OP_CHECKSIG",
            "0-gb875632ccf606eef2397124e6c2febf-Bytes:9081d463757aa7ed5213e734ea13ff66db84ba8ca70dee97e2c4ec008759d8f2-Signature:9c0ef4c0a453f41c3887b29c32a057956adcc4104e226a5f8d601b7dd9f3c6889a963e255440e6716c36d3e865c30c54fa4b3145c83053d6d8461e7f0f872b08-PubKey:2a698271b680fd389ca2dc4823a8084065b2554caf0753b5ddc57a750564b1d4-Op:OP_DUP-Op:OP_HASH256-Bytes:41063307a3fd68f3b03839c2889cd7ad0ae06259cad1be96ea4d8fa7e420d4d5-Op:OP_EQUALVERIFY-Op:OP_CHECKSIG",
            "0-g87ac5d1ddfa64329d8548b34c25ee5e-Bytes:45edc12b9c1457b82c499d90e702e29fc66474e2b8ca302bd3eb61dd2b7eb4b7-Signature:c19533e0b6d7d355f11c7f3911e05f11d9b6d50a571496e71eae223d86f42e67d69574f6313ba1c2976bbc82452caca467e74108d5cda371574746d677620000-PubKey:3549f82095030b2ca9577c828363f0fdbd92d9a131f698536e6b306cdad3f26e-Op:OP_DUP-Op:OP_HASH256-Bytes:9019b9222a630ecd26a63edd69a8e4532b07cc188903b76c649450256264503d-Op:OP_EQUALVERIFY-Op:OP_CHECKSIG",
        ];

        //
        // Verify arguments
        //

        let expected_signable_data = previous_out_points.each_ref()
            .map(|out_point| construct_tx_in_out_signable_hash(out_point, &tx_outs));
        assert_eq!(
            signable_data,
            expected_signable_data.each_ref().map(String::as_str),
            "signable_data");

        let expected_signatures = (0..TX_IN_COUNT)
            .map(|n| sign_detached(signable_data[n].as_ref(), &secret_keys[n]))
            .into_array::<[_; TX_IN_COUNT]>().unwrap();
        assert_eq!(
            signatures,
            expected_signatures,
            "signatures");

        //
        // Act
        //
        let tx_ins: [TxIn; TX_IN_COUNT] = (0..TX_IN_COUNT)
            .map(|n| {
                let sig_data = signable_data[n].to_owned();
                let sig = signatures[n];
                let pk = pub_keys[n];

                let script = Script::pay2pkh(hex::decode(&sig_data).unwrap(), sig, pk);
                let out_p = previous_out_points[n].clone();

                TxIn::P2PKH(P2PKHTxIn {
                    previous_out: out_p,
                    public_key: pk,
                    signature: sig,
                })
            })
            .into_array().unwrap();

        let actual_tx_in_address_signable_strings = tx_ins.iter().enumerate()
            .map(|tx_in| get_tx_in_address_signable_string(
                tx_version,
                tx_in,
                &tx_outs,
            ))
            .into_array::<[_; TX_IN_COUNT]>().unwrap();

        let actual_tx_ins_address = construct_tx_ins_address(
            tx_version,
            &tx_ins,
            &tx_outs,
        );

        assert_eq!(
            actual_tx_in_address_signable_strings,
            tx_in_address_signable_strings.map(str::to_owned),
            "tx_in_address_signable_string");

        assert_eq!(
            actual_tx_ins_address,
            hex::encode(sha3_256::digest(actual_tx_in_address_signable_strings.join("-").as_bytes())),
            "tx_ins_address_signable_string");

        assert_eq!(
            &actual_tx_ins_address,
            "2e647db8fbe885d3260bebf2e1ca05a2a69ce93443e4185b144b6ccb44d976b6",
            "tx_ins_address");
    }
}
