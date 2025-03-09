#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
mod private_balance {
    use ink_storage::traits::{PackedLayout, SpreadLayout};
    use zksnarks::proof_system::{verify_proof, generate_proof};

    #[derive(Debug, Default, Clone, PartialEq, Eq, PackedLayout, SpreadLayout)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct EncryptedBalance {
        proof: Vec<u8>,
        commitment: Vec<u8>,
    }

    #[ink(storage)]
    pub struct PrivateBalance {
        balances: ink_storage::collections::HashMap<AccountId, EncryptedBalance>,
    }

    impl PrivateBalance {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                balances: ink_storage::collections::HashMap::new(),
            }
        }

        #[ink(message)]
        pub fn deposit(&mut self, proof: Vec<u8>, commitment: Vec<u8>) -> bool {
            let caller = self.env().caller();
            if verify_proof(&proof) {
                self.balances.insert(caller, EncryptedBalance { proof, commitment });
                true
            } else {
                false
            }
        }

        #[ink(message)]
        pub fn get_balance(&self, account: AccountId) -> Option<EncryptedBalance> {
            self.balances.get(&account).cloned()
        }
    }
}
