#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;
use bls12_381::{G1Projective, Scalar};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use ink_storage::traits::{PackedLayout, SpreadLayout};

#[ink::contract]
mod mpc_transactions {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, PackedLayout, SpreadLayout)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct MPCSignature {
        pub r: Vec<u8>,
        pub s: Vec<u8>,
    }

    #[ink(storage)]
    pub struct MPCTransactions {
        signers: ink_storage::collections::HashMap<AccountId, MPCSignature>,
    }

    impl MPCTransactions {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                signers: ink_storage::collections::HashMap::new(),
            }
        }

        /// Menambahkan tanda tangan MPC dari setiap node
        #[ink(message)]
        pub fn add_signature(&mut self, signer: AccountId, r: Vec<u8>, s: Vec<u8>) -> bool {
            self.signers.insert(signer, MPCSignature { r, s });
            true
        }

        /// Verifikasi tanda tangan MPC menggunakan BLS12-381
        #[ink(message)]
        pub fn verify_signature(&self, msg: Vec<u8>, r: Vec<u8>, s: Vec<u8>) -> bool {
            let hashed_msg = Sha256::digest(&msg);
            let g = G1Projective::generator();
            let h = G1Projective::hash_to_curve(&hashed_msg);

            let r_scalar = Scalar::from_bytes(&r).expect("Invalid r scalar");
            let s_scalar = Scalar::from_bytes(&s).expect("Invalid s scalar");

            let lhs = g * s_scalar;
            let rhs = h * r_scalar;

            lhs == rhs
        }
    }
}
