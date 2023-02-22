use std::fs;

use core::PasswordRequest;
use methods::{PW_CHECKER_ELF, PW_CHECKER_ID};
use rand::prelude::*;
use risc0_zkp::core::sha::Digest;
use risc0_zkvm::serde::{from_slice, to_vec};
use risc0_zkvm::Prover;

fn main() {
    let mut rng = StdRng::from_entropy();
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    let request = PasswordRequest {
        password: "S00perSecr1t!!!".into(),
        salt,
    };

    // a new prover is created to run the pw_checker method
    let mut prover = Prover::new(PW_CHECKER_ELF, PW_CHECKER_ID).unwrap();

    // Adding input to the prover makes it readable by the guest
    let vec = to_vec(&request).unwrap();
    prover.add_input_u32_slice(&vec);

    let receipt = prover.run().unwrap();
    let password_hash: Digest = from_slice(&receipt.journal).unwrap();
    println!("Password hash is: {}", &password_hash);

    // In most scenarios, we would serialize and send the receipt to a verifier here
    // The verifier checks the receipt with the following call, which panics if the receipt is wrong
    receipt.verify(PW_CHECKER_ID).unwrap();
}
