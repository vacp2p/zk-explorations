use methods::{MULTIPLY_ELF, MULTIPLY_ID};
use risc0_zkvm::serde::{from_slice, to_vec};
use risc0_zkvm::Prover;

fn main() {
    let a: u64 = 37;
    let b: u64 = 67;
    let c: u64 = 11;

    let mut prover = Prover::new(MULTIPLY_ELF, MULTIPLY_ID).expect(
        "Prover should be constructed from valid method source code and corresponding method ID",
    );

    prover.add_input_u32_slice(&to_vec(&a).expect("should be serializable"));
    prover.add_input_u32_slice(&to_vec(&b).expect("should be serializable"));
    prover.add_input_u32_slice(&to_vec(&c).expect("should be serializable"));

    let receipt = prover.run()
        .expect("Valid code should be provable if it doesn't overflow the cycle limit. See `embed_methods_with_options` for information on adjusting maximum cycle count.");

    let d: u64 = from_slice(&receipt.journal).expect(
        "Journal output should deserialize into the same types (& order) that it was written",
    );

    // Print an assertion
    println!("I know the factors of {}, and I can prove it!", d);

    // Here is where one would send 'receipt' over the network...

    receipt.verify(MULTIPLY_ID).expect(
        "Code you have proven should successfully verify; did you specify the correct method ID?",
    );
}
