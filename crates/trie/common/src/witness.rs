//! Merkle trie witness.

use alloy_primitives::{Address, Bytes, B256};
use alloy_trie::EMPTY_ROOT_HASH;

/// The state witness with the relevant account and storage proofs.
#[derive(Debug, PartialEq, Eq)]
pub struct StateWitness {
    /// The state root hash.
    pub state_root: B256,
    /// Array of rlp-serialized merkle trie nodes, starting from the root node and
    /// following the path of the hashed addresses as keys.
    pub accounts_witness: Vec<Bytes>,
    /// Array of `StorageWitness` instances with the relevant storage root and storage proofs
    /// for each address.
    pub storage_witnesses: Vec<StorageWitness>,
}

impl Default for StateWitness {
    fn default() -> Self {
        Self {
            state_root: EMPTY_ROOT_HASH,
            accounts_witness: Vec::new(),
            storage_witnesses: Vec::new(),
        }
    }
}

/// The storage witness with the relevant storage root and storage proofs.
#[derive(Debug, PartialEq, Eq)]
pub struct StorageWitness {
    /// The address associated with the storage.
    pub address: Address,
    /// The storage root hash.
    pub storage_root: B256,
    /// Array of rlp-serialized merkle trie nodes starting from the storage root node and following
    /// the paths of the hashed storage slots as keys.
    pub storage_witness: Vec<Bytes>,
}
