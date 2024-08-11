use crate::{DatabaseHashedCursorFactory, DatabaseTrieCursorFactory};
use reth_db_api::transaction::DbTx;
use reth_execution_errors::StateProofError;
use reth_primitives::{keccak256, Address, B256};
use reth_trie::{
    hashed_cursor::HashedPostStateCursorFactory, proof::Proof, HashedPostState, MultiProof,
};
use reth_trie_common::AccountProof;
use std::collections::HashMap;

/// Extends [`Proof`] with operations specific for working with a database transaction.
pub trait DatabaseProof<'a, TX> {
    /// Create a new [Proof] from database transaction.
    fn from_tx(tx: &'a TX) -> Self;

    /// Generates the state proof for target account and slots on top of this [`HashedPostState`].
    fn overlay_account_proof(
        tx: &'a TX,
        post_state: HashedPostState,
        address: Address,
        slots: &[B256],
    ) -> Result<AccountProof, StateProofError>;

    /// Generates the state proof for target accounts and slots on top of this [`HashedPostState`].
    fn overlay_multiproof(
        tx: &'a TX,
        post_state: HashedPostState,
        targets: HashMap<Address, Vec<B256>>,
    ) -> Result<MultiProof, StateProofError>;
}

impl<'a, TX: DbTx> DatabaseProof<'a, TX>
    for Proof<DatabaseTrieCursorFactory<'a, TX>, DatabaseHashedCursorFactory<'a, TX>>
{
    /// Create a new [Proof] instance from database transaction.
    fn from_tx(tx: &'a TX) -> Self {
        Self::new(DatabaseTrieCursorFactory::new(tx), DatabaseHashedCursorFactory::new(tx))
    }

    fn overlay_account_proof(
        tx: &'a TX,
        post_state: HashedPostState,
        address: Address,
        slots: &[B256],
    ) -> Result<AccountProof, StateProofError> {
        let prefix_sets = post_state.construct_prefix_sets();
        let sorted = post_state.into_sorted();
        let hashed_cursor_factory =
            HashedPostStateCursorFactory::new(DatabaseHashedCursorFactory::new(tx), &sorted);
        Self::from_tx(tx)
            .with_hashed_cursor_factory(hashed_cursor_factory)
            .with_prefix_sets_mut(prefix_sets)
            .account_proof(address, slots)
    }

    fn overlay_multiproof(
        tx: &'a TX,
        post_state: HashedPostState,
        targets: HashMap<Address, Vec<B256>>,
    ) -> Result<MultiProof, StateProofError> {
        let prefix_sets = post_state.construct_prefix_sets();
        let sorted = post_state.into_sorted();
        let hashed_cursor_factory =
            HashedPostStateCursorFactory::new(DatabaseHashedCursorFactory::new(tx), &sorted);
        Self::from_tx(tx)
            .with_hashed_cursor_factory(hashed_cursor_factory)
            .with_prefix_sets_mut(prefix_sets)
            .with_targets(targets.into_iter().map(|(k, s)| (keccak256(k), s)).collect())
            .multiproof()
    }
}
