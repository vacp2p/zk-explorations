#![no_main]
#![no_std]

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let a: u64 = env::read();
    let b: u64 = env::read();
    let c: u64 = env::read();
    // Verify that neither of them are 1 (i.e. nontrivial factors)
    if a == 1 || b == 1 || c == 1 {
        panic!("Trivial factors")
    }
    let product = a.checked_mul(b).expect("Integer overflow").checked_mul(c).expect("Integer overflow");
    env::commit(&product);
}
