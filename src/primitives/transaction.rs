#![allow(unused)]
use crate::constants::*;
use crate::crypto::sign_ed25519::{PublicKey, SecretKey, Signature};
use crate::primitives::{
    asset::{Asset, ItemAsset, TokenAmount},
    druid::{DdeValues, DruidExpectation},
};
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
use crate::utils::is_valid_amount;
use serde::{Deserialize, Serialize};
use std::fmt;
use bincode::{Decode, Encode};

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

/// An outpoint - a combination of a transaction hash and an index n into its vout
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize, Encode, Decode)]
#[serde(deny_unknown_fields)]
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

/// A constructor for a `TxIn`.
#[derive(Clone, Copy, Debug)]
pub enum TxInConstructor<'a> {
    /// A constructor for a coinbase input.
    Coinbase {
        /// The number of the block which was mined.
        block_number: u64,
    },
    /// A constructor for an asset creation input.
    // TODO: jrabil: this needs to be tweaked a bit (e.g. we're still missing the GenesisHashSpec)
    Create {
        /// The block number which the asset was created at.
        block_number: u64,
        asset: &'a Asset,
        public_key: &'a PublicKey,
        secret_key: &'a SecretKey,
    },
    /// A constructor for a P2PKH input.
    P2PKH {
        /// The `OutPoint` being redeemed.
        previous_out: &'a OutPoint,
        /// The spender's public key.
        public_key: &'a PublicKey,
        /// The spender's private key.
        secret_key: &'a SecretKey,
    },
}

/// A Coinbase transaction input.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub struct CoinbaseTxIn {
    pub block_number: u64,
}

impl CoinbaseTxIn {
    /// Wraps this `CoinbaseTxIn` into a `TxIn`
    pub fn wrap(self) -> TxIn {
        TxIn::Coinbase(self)
    }
}

/*#[cfg(test)]
impl crate::utils::Placeholder for CoinbaseTxIn {
    fn placeholder() -> Self {
        Self { block_number: 0 }
    }
}*/

/// An asset creation transaction input.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub struct CreateTxIn {
    pub block_number: u64,
    pub asset_hash: Vec<u8>, // TODO: use a fixed-length type? // TODO: should we even keep this?
    pub public_key: PublicKey,
    pub signature: Signature,
}

impl CreateTxIn {
    /// Wraps this `CreateTxIn` into a `TxIn`
    pub fn wrap(self) -> TxIn {
        TxIn::Create(self)
    }
}


/*#[cfg(test)]
impl crate::utils::Placeholder for CreateTxIn {
    fn placeholder() -> Self {
        Self {
            block_number: 0,
            asset_hash: vec![],
            public_key: crate::utils::Placeholder::placeholder(),
            signature: crate::utils::Placeholder::placeholder(),
        }
    }
}*/

/// A P2PKH redeem transaction input.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Encode, Decode)]
pub struct P2PKHTxIn {
    pub previous_out: OutPoint,
    pub public_key: PublicKey,
    pub signature: Signature,
    pub check_data: Vec<u8>, // TODO: this can be inferred automatically
}

impl P2PKHTxIn {
    /// Wraps this `P2PKHTxIn` into a `TxIn`
    pub fn wrap(self) -> TxIn {
        TxIn::P2PKH(self)
    }
}

/*#[cfg(test)]
impl crate::utils::Placeholder for P2PKHTxIn {
    fn placeholder() -> Self {
        Self {
            previous_out: OutPoint::new(Default::default(), 0),
            public_key: crate::utils::Placeholder::placeholder(),
            signature: crate::utils::Placeholder::placeholder(),
        }
    }
}*/

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
}

/// The basic transaction that is broadcasted on the network and contained in
/// blocks. A transaction can contain multiple inputs and outputs.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Transaction {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub version: usize,
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
    pub fn new() -> Transaction {
        Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            fees: Vec::new(),
            version: NETWORK_VERSION as usize,
            druid_info: None,
        }
    }

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
}
