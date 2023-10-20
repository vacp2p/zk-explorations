use ark_std::{end_timer, start_timer};

use std::{collections::HashMap, env, env::current_dir, time::Instant};

use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F1,
    G2, S1, S2,
};
// Ignore create_recursive_circuit

use nova_snark::{traits::Group, CompressedSNARK};

extern crate wee_alloc;

// NOTE: Supposedly this helps against segfaults, but seems intermittent
// Consider trying jemallocator (?)
// Alternatively, just run larger benchmarks on a server (with C++ version)
//
// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

fn recursive_hashing(depth: usize) {
    println! {"Using recursive depth: {:?} times depth_per_fold in circuit (default 10 or 100, check yourself! :D)", depth};

    let iteration_count = depth;
    let root = current_dir().unwrap();

    let circuit_file = root.join("./examples/poseidon/circom/poseidon_test_nova.r1cs");
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_wasm =
        root.join("./examples/poseidon/circom/poseidon_test_nova_js/poseidon_test_nova.wasm");

    let step_in_vector = vec![0, 1, 2, 3];

    let mut private_inputs = Vec::new();
    for _ in 0..iteration_count {
        let private_input = HashMap::new();
        private_inputs.push(private_input);
    }

    let start_public_input = step_in_vector
        .into_iter()
        .map(|x| F1::from(x))
        .collect::<Vec<_>>();

    let pp = create_public_params(r1cs.clone());

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    // create a recursive SNARK
    let timer_create_proof = start_timer!(|| "Create RecursiveSNARK");
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_wasm),
        r1cs,
        private_inputs,
        start_public_input.clone(),
        &pp,
    )
    .unwrap();
    end_timer!(timer_create_proof);

    // TODO: empty?
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let timer_verify_snark = start_timer!(|| "verify SNARK");
    let res = recursive_snark.verify(
        &pp,
        iteration_count,
        start_public_input.clone(),
        z0_secondary.clone(),
    );
    assert!(res.is_ok());

    end_timer!(timer_verify_snark);

    // produce a compressed SNARK
    let timer_gen_compressed_snark =
        start_timer!(|| "Generate a CompressedSNARK using Spartan with IPA-PC");
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();
    end_timer!(timer_gen_compressed_snark);

    let timer_verify_compressed_snark = start_timer!(|| "Verify CompressedSNARK");
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.clone(),
        z0_secondary,
    );
    end_timer!(timer_verify_compressed_snark);

    assert!(res.is_ok());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    // let k: usize = args[1].parse().unwrap();
    let k = 10;
    //let poseidon_block: u64 = args[2].parse().unwrap();

    // NOTE: Toggle here
    recursive_hashing(k);
}
