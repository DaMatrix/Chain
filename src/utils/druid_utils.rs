use tracing::info;

use crate::primitives::asset::Asset;
use crate::primitives::druid::DruidExpectation;
use crate::primitives::transaction::Transaction;
use crate::utils::transaction_utils::construct_tx_ins_address;
use std::collections::BTreeSet;
use std::iter::Extend;
use crate::primitives::address::AnyAddress;

/// Verifies that all DDE transaction expectations are met for DRUID-matching transactions
///
/// ### Arguments
///
/// * `druid`           - DRUID to match all transactions on
/// * `transactions`    - Transactions to verify
pub fn druid_expectations_are_met<'a>(
    druid: &str,
    transactions: impl Iterator<Item = &'a Transaction>,
) -> bool {
    let mut expects = BTreeSet::new();
    let mut tx_source = BTreeSet::new();

    for tx in transactions {
        info!("");
        if let Some(druid_info) = &tx.druid_info {
            let ins = construct_tx_ins_address(tx.version, &tx.inputs, &tx.outputs);

            // Ensure match with passed DRUID
            if druid_info.druid == druid {
                info!("DRUIDs match");
                expects.extend(druid_info.expectations.iter());

                info!("Expectations: {:?}", expects);

                for out in &tx.outputs {
                    match &out.script_public_key {
                        AnyAddress::P2PKH(p2pkh) =>
                            tx_source.insert((ins.clone(), p2pkh.to_string(), &out.value)),
                        AnyAddress::Burn => false,
                    };
                }
                info!("Tx Source: {:?}", tx_source);
            }
        }
        info!("");
    }

    expects.iter().all(|e| expectation_met(e, &tx_source))
}

/// Predicate for expected transaction presence in the transaction set
///
/// ### Arguments
///
/// * `e`           - The expectation to check on
/// * `tx_source`   - The source transaction source to match against
fn expectation_met(e: &DruidExpectation, tx_source: &BTreeSet<(String, String, &Asset)>) -> bool {
    tx_source.contains(&(e.from.clone(), e.to.clone(), &e.asset))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::vec;

    use super::*;
    use crate::crypto::sign_ed25519::{self as sign};
    use crate::primitives::address::{AnyAddress, P2PKHAddress};
    use crate::primitives::asset::{Asset, ItemAsset, TokenAmount};
    use crate::primitives::druid::{DdeValues, DruidExpectation};
    use crate::primitives::transaction::*;
    use crate::utils::Placeholder;
    use crate::utils::transaction_utils::*;

    /// Util function to create valid DDE asset tx's
    fn create_dde_txs() -> Vec<Transaction> {
        let druid = "VALUE".to_owned();
        let from_addr = construct_tx_ins_address(TxVersion::V6, &[], &[]);

        let (pk, sk) = sign::gen_test_keypair(0).unwrap();
        let prev_out = OutPoint::placeholder();
        let mut key_material = BTreeMap::new();
        key_material.insert(prev_out, (pk, sk));

        // Alice
        let amount = TokenAmount(10);
        let alice_addr = P2PKHAddress::placeholder_indexed(0).wrap();
        let alice_asset = Asset::Token(amount);

        // Bob
        let bob_asset = Asset::Item(ItemAsset {
            metadata: Some("453094573049875".to_string()),
            amount: 1,
            genesis_hash: None,
        });
        let bob_addr = P2PKHAddress::placeholder_indexed(1).wrap();

        // TxOuts
        let token_tx_out = TxOut::new_asset(bob_addr.clone(), alice_asset.clone(), None);
        let data_tx_out = TxOut::new_asset(alice_addr.clone(), bob_asset.clone(), None);

        // Expectations (from addresses the same due to empty TxIn)
        let expects = vec![
            DruidExpectation {
                from: from_addr.clone(),
                to: bob_addr.to_string(),
                asset: alice_asset,
            },
            DruidExpectation {
                from: from_addr,
                to: alice_addr.to_string(),
                asset: bob_asset,
            },
        ];

        // Txs
        let tx_input = vec![];
        let alice_druid_info = DdeValues {
            druid: druid.clone(),
            participants: 2,
            expectations: expects.clone(),
            genesis_hash: None,
        };
        let alice_tx =
            construct_dde_tx(alice_druid_info, tx_input.clone(), vec![token_tx_out], None, &key_material);

        let bob_druid_info = DdeValues {
            druid: druid.clone(),
            participants: 2,
            expectations: expects.clone(),
            genesis_hash: None,
        };
        let bob_tx = construct_dde_tx(bob_druid_info, tx_input, vec![data_tx_out], None, &key_material);

        vec![alice_tx, bob_tx]
    }

    /// Util function to create valid item-based payment tx's
    fn create_rb_payment_txs() -> (Transaction, Transaction) {
        // Arrange
        //
        let amount = TokenAmount(33);
        let payment = TokenAmount(11);
        let druid = "VALUE".to_owned();

        let from_addr = construct_tx_ins_address(TxVersion::V6, &[], &[]);

        let alice_addr = P2PKHAddress::placeholder_indexed(0).wrap();
        let bob_addr = P2PKHAddress::placeholder_indexed(1).wrap();

        let sender_address_excess = P2PKHAddress::placeholder_indexed(2).wrap();
        let mut key_material = BTreeMap::new();

        let genesis_hash = TxHash::placeholder_indexed(0);

        // Act
        //
        let send_tx = {
            let tx_ins = vec![];
            let excess_tx_out =
                TxOut::new_token_amount(sender_address_excess, amount - payment, None);
            
            let (pk, sk) = sign::gen_test_keypair(0).unwrap();
            let prev_out = OutPoint::placeholder();
            key_material.insert(prev_out, (pk, sk));

            let expectation = DruidExpectation {
                from: from_addr.clone(),
                to: alice_addr.to_string(),
                asset: Asset::item(1, Some(genesis_hash.clone()), None),
            };

            let druid_info = DdeValues {
                druid: druid.clone(),
                participants: 2,
                expectations: vec![expectation.clone()],
                genesis_hash: None,
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
                druid_info,
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
                expectations: vec![expectation.clone()],
                genesis_hash: Some(genesis_hash.to_string()),
            };

            // create the sender that match the receiver.
            construct_rb_receive_payment_tx(tx_ins, Vec::new(), None, alice_addr, 0, druid_info, &key_material)
        };

        (send_tx, recv_tx)
    }

    #[test]
    /// Checks that matching DDE transactions are verified as such by DDE verifier
    fn should_pass_matching_dde_tx_valid() {
        let txs = create_dde_txs();
        assert!(druid_expectations_are_met("VALUE", txs.iter()));
    }

    #[test]
    /// Checks that DDE transactions with non-matching expects fail
    fn should_fail_dde_tx_value_expect_mismatch() {
        let mut txs = create_dde_txs();
        let mut change_tx = txs.pop().unwrap();
        let orig_tx = txs[0].clone();

        let druid_info = change_tx.druid_info.clone();
        let mut expects = druid_info.unwrap().expectations;
        expects[0].to = "60764505679457".to_string();

        // New druid info
        let nm_druid_info = DdeValues {
            druid: "VALUE".to_owned(),
            participants: 2,
            expectations: expects,
            genesis_hash: None,
        };
        change_tx.druid_info = Some(nm_druid_info);

        assert!(!druid_expectations_are_met(
            "VALUE",
            vec![orig_tx, change_tx].iter()
        ));
    }

    #[test]
    /// Checks that matching item-based payments are verified as such by the DDE verifier
    fn should_pass_matching_rb_payment_valid() {
        let (send_tx, recv_tx) = create_rb_payment_txs();
        assert!(druid_expectations_are_met(
            "VALUE",
            vec![send_tx, recv_tx].iter()
        ));
    }

    #[test]
    /// Checks that item-based payments with non-matching DRUIDs fail
    fn should_fail_rb_payment_druid_mismatch() {
        let (send_tx, mut recv_tx) = create_rb_payment_txs();

        let mut druid_info = recv_tx.druid_info.unwrap();
        druid_info.druid = "Not_VAlue".to_owned();
        recv_tx.druid_info = Some(druid_info);

        // Non-matching druid
        assert!(!druid_expectations_are_met(
            "VALUE",
            vec![send_tx, recv_tx].iter()
        ));
    }

    #[test]
    /// Checks that item-based payments with non-matching addresses fail
    fn should_fail_rb_payment_addr_mismatch() {
        let (send_tx, mut recv_tx) = create_rb_payment_txs();
        recv_tx.outputs[0].script_public_key = AnyAddress::P2PKH(P2PKHAddress::placeholder_indexed(1337));

        // Non-matching address expectation
        assert!(!druid_expectations_are_met(
            "VALUE",
            vec![send_tx, recv_tx].iter()
        ));
    }

    #[test]
    /// Checks that item-based payments with non-matching value expectations fail
    fn should_fail_rb_payment_value_expect_mismatch() {
        let (mut send_tx, recv_tx) = create_rb_payment_txs();
        send_tx.outputs[0].value = Asset::token_u64(10);

        // Non-matching address expectation
        assert!(!druid_expectations_are_met(
            "VALUE",
            vec![send_tx, recv_tx].iter()
        ));
    }

    #[test]
    /// Checks that item-based payments with non-matching DRS expectations fail
    fn should_fail_rb_payment_drs_expect_mismatch() {
        let (send_tx, mut recv_tx) = create_rb_payment_txs();
        let invalid_genesis_hash = TxHash::placeholder_indexed(1337);
        recv_tx.outputs[0].value = Asset::item(1, Some(invalid_genesis_hash), None);

        // Non-matching address expectation
        assert!(!druid_expectations_are_met(
            "VALUE",
            vec![send_tx, recv_tx].iter()
        ));
    }
}
