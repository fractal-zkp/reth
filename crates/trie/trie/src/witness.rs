use crate::{
    hashed_cursor::{HashedCursorFactory, HashedStorageCursor},
    node_iter::{TrieElement, TrieNodeIter},
    prefix_set::TriePrefixSetsMut,
    trie_cursor::{DatabaseAccountTrieCursor, DatabaseStorageTrieCursor},
    walker::TrieWalker,
    HashBuilder, Nibbles,
};
use alloy_rlp::{BufMut, Encodable};
use reth_db::tables;
use reth_db_api::transaction::DbTx;
use reth_execution_errors::{StateRootError, StorageRootError};
use reth_primitives::{constants::EMPTY_ROOT_HASH, keccak256, Address, Bytes, B256};
use reth_trie_common::{proof::ProofRetainer, StateWitness, StorageWitness, TrieAccount};

/// A struct for generating merkle witnesses.
///
/// Witness generator adds the target address and slots to the prefix set, enables the proof
/// retainer on the hash builder and follows the same algorithm as the state root calculator.
/// See `StateRoot::root` for more info.
#[derive(Debug)]
pub struct Witness<'a, TX, H> {
    /// A reference to the database transaction.
    tx: &'a TX,
    /// The factory for hashed cursors.
    hashed_cursor_factory: H,
    /// A set of prefix sets that have changes.
    prefix_sets: TriePrefixSetsMut,
}

impl<'a, TX, H> Witness<'a, TX, H> {
    /// Create a new [Witness] instance.
    pub fn new(tx: &'a TX, hashed_cursor_factory: H) -> Self {
        Self { tx, hashed_cursor_factory, prefix_sets: TriePrefixSetsMut::default() }
    }

    /// Set the hashed cursor factory.
    pub fn with_hashed_cursor_factory<HF>(self, hashed_cursor_factory: HF) -> Witness<'a, TX, HF> {
        Witness { tx: self.tx, hashed_cursor_factory, prefix_sets: self.prefix_sets }
    }

    /// Set the prefix sets. They have to be mutable in order to allow extension with proof target.
    pub fn with_prefix_sets_mut(mut self, prefix_sets: TriePrefixSetsMut) -> Self {
        self.prefix_sets = prefix_sets;
        self
    }
}

impl<'a, TX> Witness<'a, TX, &'a TX> {
    /// Create a new [Witness] instance from database transaction.
    pub fn from_tx(tx: &'a TX) -> Self {
        Self::new(tx, tx)
    }
}

impl<'a, TX, H> Witness<'a, TX, H>
where
    TX: DbTx,
    H: HashedCursorFactory + Clone,
{
    /// Generates a state witness for the given targets.
    pub fn state_witness(
        &self,
        targets: Vec<(Address, Vec<B256>)>,
    ) -> Result<StateWitness, StateRootError> {
        let target_accounts: Vec<(Nibbles, Address, Vec<B256>)> = targets
            .into_iter()
            .map(|(address, slots)| {
                let hashed_address = keccak256(address);
                let hashed_address_nibbles = Nibbles::unpack(hashed_address);
                (hashed_address_nibbles, address, slots)
            })
            .collect();

        let hashed_account_cursor = self.hashed_cursor_factory.hashed_account_cursor()?;
        let trie_cursor =
            DatabaseAccountTrieCursor::new(self.tx.cursor_read::<tables::AccountsTrie>()?);

        // Create the account walker.
        let mut prefix_set = self.prefix_sets.account_prefix_set.clone();
        target_accounts.iter().for_each(|(nibbles, _, _)| {
            prefix_set.insert(nibbles.clone());
        });
        let walker = TrieWalker::new(trie_cursor, prefix_set.freeze());

        // Create a hash builder to rebuild the root node since it is not available in the database.
        let retainer =
            ProofRetainer::from_iter(target_accounts.iter().map(|(nibbles, _, _)| nibbles.clone()));
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);

        let mut storage_witnesses = vec![];
        let mut account_rlp = Vec::with_capacity(128);
        let mut account_node_iter = TrieNodeIter::new(walker, hashed_account_cursor);
        while let Some(account_node) = account_node_iter.try_next()? {
            match account_node {
                TrieElement::Branch(node) => {
                    hash_builder.add_branch(node.key, node.value, node.children_are_in_trie);
                }
                TrieElement::Leaf(hashed_address, account) => {
                    let nibbles = Nibbles::unpack(hashed_address);
                    let storage_root = if let Some((_, address, slots)) =
                        target_accounts.iter().find(|(n, _, _)| n == &nibbles)
                    {
                        let (storage_root, storage_proofs) =
                            self.storage_root_with_witness(hashed_address, slots)?;
                        storage_witnesses.push(StorageWitness {
                            address: *address,
                            storage_root,
                            storage_witness: storage_proofs,
                        });
                        storage_root
                    } else {
                        self.storage_root(hashed_address)?
                    };

                    account_rlp.clear();
                    let account = TrieAccount::from((account, storage_root));
                    account.encode(&mut account_rlp as &mut dyn BufMut);

                    hash_builder.add_leaf(Nibbles::unpack(hashed_address), &account_rlp);
                }
            }
        }

        let root = hash_builder.root();
        let proofs = hash_builder.take_proofs();

        Ok(StateWitness {
            state_root: root,
            accounts_witness: proofs.values().cloned().collect(),
            storage_witnesses,
        })
    }

    fn storage_root_with_witness(
        &self,
        hashed_address: B256,
        slots: &[B256],
    ) -> Result<(B256, Vec<Bytes>), StorageRootError> {
        let mut hashed_storage_cursor =
            self.hashed_cursor_factory.hashed_storage_cursor(hashed_address)?;

        // short circuit on empty storage
        if hashed_storage_cursor.is_storage_empty()? {
            return Ok((EMPTY_ROOT_HASH, vec![]));
        }

        let target_nibbles =
            slots.iter().map(|slot| Nibbles::unpack(keccak256(slot))).collect::<Vec<_>>();
        let mut prefix_set =
            self.prefix_sets.storage_prefix_sets.get(&hashed_address).cloned().unwrap_or_default();
        prefix_set.extend(target_nibbles.clone());
        let trie_cursor = DatabaseStorageTrieCursor::new(
            self.tx.cursor_dup_read::<tables::StoragesTrie>()?,
            hashed_address,
        );
        let walker = TrieWalker::new(trie_cursor, prefix_set.freeze());

        let retainer = ProofRetainer::from_iter(target_nibbles);
        let mut hash_builder = HashBuilder::default().with_proof_retainer(retainer);
        let mut storage_node_iter = TrieNodeIter::new(walker, hashed_storage_cursor);
        while let Some(node) = storage_node_iter.try_next()? {
            match node {
                TrieElement::Branch(node) => {
                    hash_builder.add_branch(node.key, node.value, node.children_are_in_trie);
                }
                TrieElement::Leaf(hashed_slot, value) => {
                    let nibbles = Nibbles::unpack(hashed_slot);
                    hash_builder.add_leaf(nibbles, alloy_rlp::encode_fixed_size(&value).as_ref());
                }
            }
        }

        let root = hash_builder.root();
        let proofs = hash_builder.take_proofs();

        Ok((root, proofs.values().cloned().collect()))
    }

    fn storage_root(&self, hashed_address: B256) -> Result<B256, StorageRootError> {
        let (storage_root, _) = self.storage_root_with_witness(hashed_address, &[])?;
        Ok(storage_root)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::proof::tests::{convert_to_proof, insert_genesis, TEST_SPEC},
        *,
    };
    use reth_chainspec::HOLESKY;
    use reth_provider::test_utils::create_test_provider_factory;
    use std::str::FromStr;

    #[test]
    fn testspec_witness() {
        // Create test database and insert genesis accounts.
        let factory = create_test_provider_factory();
        let root = insert_genesis(&factory, TEST_SPEC.clone()).unwrap();

        let data = Vec::from([
            (
                vec!["0x2031f89b3ea8014eb51a78c316e42af3e0d7695f"],
                convert_to_proof([
                    "0xe48200a7a040f916999be583c572cc4dd369ec53b0a99f7de95f13880cf203d98f935ed1b3",
                    "0xf87180a04fb9bab4bb88c062f32452b7c94c8f64d07b5851d44a39f1e32ba4b1829fdbfb8080808080a0b61eeb2eb82808b73c4ad14140a2836689f4ab8445d69dd40554eaf1fce34bc080808080808080a0dea230ff2026e65de419288183a340125b04b8405cc61627b3b4137e2260a1e880",
                    "0xf8719f31355ec1c8f7e26bb3ccbcb0b75d870d15846c0b98e5cc452db46c37faea40b84ff84d80890270801d946c940000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                ])
            ),
            (
                vec!["0x2031f89b3ea8014eb51a78c316e42af3e0d7695f", "0x33f0fc440b8477fcfbe9d0bf8649e7dea9baedb2"],
                convert_to_proof([
                    "0xe48200a7a040f916999be583c572cc4dd369ec53b0a99f7de95f13880cf203d98f935ed1b3",
                    "0xf87180a04fb9bab4bb88c062f32452b7c94c8f64d07b5851d44a39f1e32ba4b1829fdbfb8080808080a0b61eeb2eb82808b73c4ad14140a2836689f4ab8445d69dd40554eaf1fce34bc080808080808080a0dea230ff2026e65de419288183a340125b04b8405cc61627b3b4137e2260a1e880",
                    "0xf8719f31355ec1c8f7e26bb3ccbcb0b75d870d15846c0b98e5cc452db46c37faea40b84ff84d80890270801d946c940000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    "0xe48200d3a0ef957210bca5b9b402d614eb8408c88cfbf4913eb6ab83ca233c8b8f0e626b54",
                    "0xf851808080a02743a5addaf4cf9b8c0c073e1eaa555deaaf8c41cb2b41958e88624fa45c2d908080808080a0bfbf6937911dfb88113fecdaa6bde822e4e99dae62489fcf61a91cb2f36793d680808080808080",
                    "0xf8679e207781e762f3577784bab7491fcc43e291ce5a356b9bc517ac52eed3a37ab846f8448001a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                ])
            ),
            (
                vec!["0x62b0dd4aab2b1a0a04e279e2b828791a10755528"],
                convert_to_proof([
                    "0xe48200a7a040f916999be583c572cc4dd369ec53b0a99f7de95f13880cf203d98f935ed1b3",
                    "0xf87180a04fb9bab4bb88c062f32452b7c94c8f64d07b5851d44a39f1e32ba4b1829fdbfb8080808080a0b61eeb2eb82808b73c4ad14140a2836689f4ab8445d69dd40554eaf1fce34bc080808080808080a0dea230ff2026e65de419288183a340125b04b8405cc61627b3b4137e2260a1e880",
                    "0xf8709f3936599f93b769acf90c7178fd2ddcac1b5b4bc9949ee5a04b7e0823c2446eb84ef84c80880f43fc2c04ee0000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                ])
            ),
            (
                vec!["0x1ed9b1dd266b607ee278726d324b855a093394a6", "0x62b0dd4aab2b1a0a04e279e2b828791a10755528"],
                convert_to_proof([
                    "0xe48200a7a040f916999be583c572cc4dd369ec53b0a99f7de95f13880cf203d98f935ed1b3",
                    "0xf87180a04fb9bab4bb88c062f32452b7c94c8f64d07b5851d44a39f1e32ba4b1829fdbfb8080808080a0b61eeb2eb82808b73c4ad14140a2836689f4ab8445d69dd40554eaf1fce34bc080808080808080a0dea230ff2026e65de419288183a340125b04b8405cc61627b3b4137e2260a1e880",
                    "0xe48200d3a0ef957210bca5b9b402d614eb8408c88cfbf4913eb6ab83ca233c8b8f0e626b54",
                    "0xf851808080a02743a5addaf4cf9b8c0c073e1eaa555deaaf8c41cb2b41958e88624fa45c2d908080808080a0bfbf6937911dfb88113fecdaa6bde822e4e99dae62489fcf61a91cb2f36793d680808080808080",
                    "0xf86f9e207a32b8ab5eb4b043c65b1f00c93f517bc8883c5cd31baf8e8a279475e3b84ef84c808801aa535d3d0c0000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                    "0xf8709f3936599f93b769acf90c7178fd2ddcac1b5b4bc9949ee5a04b7e0823c2446eb84ef84c80880f43fc2c04ee0000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
                ])
            ),
        ]);

        let provider = factory.provider().unwrap();
        for (addresses, expected_proof) in data {
            let targets = addresses
                .iter()
                .cloned()
                .map(|address| (Address::from_str(address).unwrap(), vec![]))
                .collect::<Vec<_>>();
            let state_witness =
                Witness::from_tx(provider.tx_ref()).state_witness(targets.clone()).unwrap();
            let expected = StateWitness {
                state_root: root,
                accounts_witness: expected_proof,
                storage_witnesses: addresses
                    .into_iter()
                    .map(|address| StorageWitness {
                        address: Address::from_str(address).unwrap(),
                        storage_root: EMPTY_ROOT_HASH,
                        storage_witness: vec![],
                    })
                    .collect(),
            };
            similar_asserts::assert_eq!(
                state_witness,
                expected,
                "proof for {targets:?} does not match"
            );
        }
    }

    #[test]
    fn testspec_empty_storage_witness() {
        // Create test database and insert genesis accounts.
        let factory = create_test_provider_factory();
        let root = insert_genesis(&factory, TEST_SPEC.clone()).unwrap();

        let address = Address::from_str("0x1ed9b1dd266b607ee278726d324b855a093394a6").unwrap();
        let slots = Vec::from([B256::with_last_byte(1), B256::with_last_byte(3)]);

        let provider = factory.provider().unwrap();
        let witness =
            Witness::from_tx(provider.tx_ref()).state_witness(vec![(address, slots)]).unwrap();

        assert_eq!(1, witness.storage_witnesses.len());
        let expected = StateWitness {
            state_root: root,
            accounts_witness: convert_to_proof([
                "0xe48200a7a040f916999be583c572cc4dd369ec53b0a99f7de95f13880cf203d98f935ed1b3",
                "0xf87180a04fb9bab4bb88c062f32452b7c94c8f64d07b5851d44a39f1e32ba4b1829fdbfb8080808080a0b61eeb2eb82808b73c4ad14140a2836689f4ab8445d69dd40554eaf1fce34bc080808080808080a0dea230ff2026e65de419288183a340125b04b8405cc61627b3b4137e2260a1e880",
                "0xe48200d3a0ef957210bca5b9b402d614eb8408c88cfbf4913eb6ab83ca233c8b8f0e626b54",
                "0xf851808080a02743a5addaf4cf9b8c0c073e1eaa555deaaf8c41cb2b41958e88624fa45c2d908080808080a0bfbf6937911dfb88113fecdaa6bde822e4e99dae62489fcf61a91cb2f36793d680808080808080",
                "0xf86f9e207a32b8ab5eb4b043c65b1f00c93f517bc8883c5cd31baf8e8a279475e3b84ef84c808801aa535d3d0c0000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
            ]),
            storage_witnesses: vec![StorageWitness {
                address,
                storage_root: EMPTY_ROOT_HASH,
                storage_witness: vec![]
            }]
        };
        similar_asserts::assert_eq!(witness, expected);
    }

    #[test]
    fn holesky_deposit_contract_witness() {
        // Create test database and insert genesis accounts.
        let factory = create_test_provider_factory();
        let root = insert_genesis(&factory, HOLESKY.clone()).unwrap();

        let target = Address::from_str("0x4242424242424242424242424242424242424242").unwrap();
        // existent
        let slot_22 =
            B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000022")
                .unwrap();
        let slot_23 =
            B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000023")
                .unwrap();
        let slot_24 =
            B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000024")
                .unwrap();
        // non-existent
        let slot_100 =
            B256::from_str("0x0000000000000000000000000000000000000000000000000000000000000100")
                .unwrap();
        let slots = Vec::from([slot_22, slot_23, slot_24, slot_100]);

        let expected = StateWitness {
            state_root: root,
            accounts_witness: convert_to_proof([
                "0xf90211a0ea92fb71507739d5afe328d607b2c5e98322b7aa7cdfeccf817543058b54af70a0bd0c2525b5bee47abf7120c9e01ec3249699d687f80ebb96ed9ad9de913dbab0a0ab4b14b89416eb23c6b64204fa45cfcb39d4220016a9cd0815ebb751fe45eb71a0986ae29c2148b9e61f9a7543f44a1f8d029f1c5095b359652e9ec94e64b5d393a0555d54aa23ed990b0488153418637df7b2c878b604eb761aa2673b609937b0eba0140afb6a3909cc6047b3d44af13fc83f161a7e4c4ddba430a2841862912eb222a031b1185c1f455022d9e42ce04a71f174eb9441b1ada67449510500f4d85b3b22a051ecd01e18113b23cc65e62f67d69b33ee15d20bf81a6b524f7df90ded00ca15a0703769d6a7befad000bc2b4faae3e41b809b1b1241fe2964262554e7e3603488a0e5de7f600e4e6c3c3e5630e0c66f50506a17c9715642fccb63667e81397bbf93a095f783cd1d464a60e3c8adcadc28c6eb9fec7306664df39553be41dccc909606a04225fda3b89f0c59bf40129d1d5e5c3bf67a2129f0c55e53ffdd2cebf185d644a078e0f7fd3ae5a9bc90f66169614211b48fe235eb64818b3935d3e69c53523b9aa0a870e00e53ebaa1e9ec16e5f36606fd7d21d3a3c96894c0a2a23550949d4fdf7a0809226b69cee1f4f22ced1974e7805230da1909036a49a7652428999431afac2a0f11593b2407e86e11997325d8df2d22d937bbe0aef8302ba40c6be0601b04fc380",
                "0xf901f1a09da7d9755fe0c558b3c3de9fdcdf9f28ae641f38c9787b05b73ab22ae53af3e2a0d9990bf0b810d1145ecb2b011fd68c63cc85564e6724166fd4a9520180706e5fa05f5f09855df46330aa310e8d6be5fb82d1a4b975782d9b29acf06ac8d3e72b1ca0ca976997ddaf06f18992f6207e4f6a05979d07acead96568058789017cc6d06ba04d78166b48044fdc28ed22d2fd39c8df6f8aaa04cb71d3a17286856f6893ff83a004f8c7cc4f1335182a1709fb28fc67d52e59878480210abcba864d5d1fd4a066a0fc3b71c33e2e6b77c5e494c1db7fdbb447473f003daf378c7a63ba9bf3f0049d80a07b8e7a21c1178d28074f157b50fca85ee25c12568ff8e9706dcbcdacb77bf854a0973274526811393ea0bf4811ca9077531db00d06b86237a2ecd683f55ba4bcb0a03a93d726d7487874e51b52d8d534c63aa2a689df18e3b307c0d6cb0a388b00f3a06aa67101d011d1c22fe739ef83b04b5214a3e2f8e1a2625d8bfdb116b447e86fa02dd545b33c62d33a183e127a08a4767fba891d9f3b94fc20a2ca02600d6d1fffa0f3b039a4f32349e85c782d1164c1890e5bf16badc9ee4cf827db6afd2229dde6a0d9240a9d2d5851d05a97ff3305334dfdb0101e1e321fc279d2bb3cad6afa8fc8a01b69c6ab5173de8a8ec53a6ebba965713a4cc7feb86cb3e230def37c230ca2b280",
                "0xf869a0202a47fc6863b89a6b51890ef3c1550d560886c027141d2058ba1e2d4c66d99ab846f8448080a0556a482068355939c95a3412bdb21213a301483edb1b64402fb66ac9f3583599a02034f79e0e33b0ae6bef948532021baceb116adf2616478703bec6b17329f1cc"
                ]),
            storage_witnesses: vec![StorageWitness {
                address: target,
                storage_root: B256::from_str("0x556a482068355939c95a3412bdb21213a301483edb1b64402fb66ac9f3583599")
                        .unwrap(),
                storage_witness: convert_to_proof([
                        "0xf9019180a0aafd5b14a6edacd149e110ba6776a654f2dbffca340902be933d011113f2750380a0a502c93b1918c4c6534d4593ae03a5a23fa10ebc30ffb7080b297bff2446e42da02eb2bf45fd443bd1df8b6f9c09726a4c6252a0f7896a131a081e39a7f644b38980a0a9cf7f673a0bce76fd40332afe8601542910b48dea44e93933a3e5e930da5d19a0ddf79db0a36d0c8134ba143bcb541cd4795a9a2bae8aca0ba24b8d8963c2a77da0b973ec0f48f710bf79f63688485755cbe87f9d4c68326bb83c26af620802a80ea0f0855349af6bf84afc8bca2eda31c8ef8c5139be1929eeb3da4ba6b68a818cb0a0c271e189aeeb1db5d59d7fe87d7d6327bbe7cfa389619016459196497de3ccdea0e7503ba5799e77aa31bbe1310c312ca17b2c5bcc8fa38f266675e8f154c2516ba09278b846696d37213ab9d20a5eb42b03db3173ce490a2ef3b2f3b3600579fc63a0e9041059114f9c910adeca12dbba1fef79b2e2c8899f2d7213cd22dfe4310561a047c59da56bb2bf348c9dd2a2e8f5538a92b904b661cfe54a4298b85868bbe4858080",
                        "0xf891a090bacef44b189ddffdc5f22edc70fe298c58e5e523e6e1dfdf7dbc6d657f7d1b80a026eed68746028bc369eb456b7d3ee475aa16f34e5eaa0c98fdedb9c59ebc53b0808080a09ce86197173e14e0633db84ce8eea32c5454eebe954779255644b45b717e8841808080a0328c7afb2c58ef3f8c4117a8ebd336f1a61d24591067ed9c5aae94796cac987d808080808080",
                        "0xf85180a0776aa456ba9c5008e03b82b841a9cf2fc1e8578cfacd5c9015804eae315f17fb80808080808080808080808080a072e3e284d47badbb0a5ca1421e1179d3ea90cc10785b26b74fb8a81f0f9e841880",
                        "0xf843a020035b26e3e9eee00e0d72fd1ee8ddca6894550dca6916ea2ac6baa90d11e510a1a0f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
                        "0xf85180808080a030263404acfee103d0b1019053ff3240fce433c69b709831673285fa5887ce4c80808080808080a0f8f1fbb1f7b482d9860480feebb83ff54a8b6ec1ead61cc7d2f25d7c01659f9c80808080",
                        "0xf843a020d332d19b93bcabe3cce7ca0c18a052f57e5fd03b4758a09f30f5ddc4b22ec4a1a0c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c",
                        "0xf8518080808080a0d546c4ca227a267d29796643032422374624ed109b3d94848c5dc06baceaee76808080808080a027c48e210ccc6e01686be2d4a199d35f0e1e8df624a8d3a17c163be8861acd6680808080",
                        "0xf843a0207b2b5166478fd4318d2acc6cc2c704584312bdd8781b32d5d06abda57f4230a1a0db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
                    ])}
        ],};

        let provider = factory.provider().unwrap();
        let witness =
            Witness::from_tx(provider.tx_ref()).state_witness(vec![(target, slots)]).unwrap();
        similar_asserts::assert_eq!(witness, expected);
    }
}
