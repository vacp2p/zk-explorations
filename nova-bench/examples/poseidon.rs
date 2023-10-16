use ark_std::{end_timer, start_timer};

use std::{collections::HashMap, env, env::current_dir, time::Instant};

use ff::derive::bitvec::vec;
use ff::PrimeField;
use nova_scotia::{
    circom::{circuit::CircomCircuit, reader::load_r1cs},
    create_public_params, create_public_params_par, create_recursive_circuit, FileLocation, F1, F2,
    G1, G2, S1, S2,
};
// Ignore create_recursive_circuit

use nova_snark::{
    parallel_prover::{FoldInput, NovaTreeNode, PublicParams},
    traits::{circuit::TrivialTestCircuit, Group},
    CompressedSNARK,
};
use num_bigint::BigInt;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use serde_json::json;

use sha2::{Digest, Sha256};

extern crate wee_alloc;

// NOTE: Supposedly this helps against segfaults, but seems intermittent
// Consider trying jemallocator (?)
// Alternatively, just run larger benchmarks on a server (with C++ version)
//
// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// TODO: Add naive Keccak circuit (check one step vs vanilla Circom)

fn gen_nth_poseidon_hash(n: usize) -> Vec<u64> {
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, One, PrimeField, Zero};
    use light_poseidon::{parameters::bn254_x5, Poseidon, PoseidonHasher};

    let mut input0 = Fr::zero();
    let mut input1 = Fr::one();
    let mut input2 = Fr::from(2);
    let mut input3 = Fr::from(3);

    // let hash = poseidon.hash_vec(&[input0, input1, input2, input3], 4).unwrap();

    // let binding = hash[0].into_bigint();
    // let array: Result<[u64; 4], _> = binding.as_ref().try_into();
    // let a: [u64; 4]  = array.unwrap();

    // println!("hash is {:?}", hash);
    // println!("a is {:?}", a);

    let mut hash = vec![];
    for _ in 0..n {
        let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();

        hash = poseidon
            .hash_vec(&[input0, input1, input2, input3], 4)
            .unwrap();
        input0 = hash[0];
        input1 = hash[1];
        input2 = hash[2];
        input3 = hash[3];
    }

    let pre_res: Vec<Vec<u64>> = hash
        .iter_mut()
        .map(|item| {
            let binding = item.into_bigint();
            let array: Result<[u64; 4], _> = binding.as_ref().try_into();
            let a: [u64; 4] = array.unwrap();
            a.to_vec()
        })
        .collect();

    let res: Vec<u64> = pre_res.into_iter().flatten().collect();

    // println!("res is {:?}", res);
    res
}

fn recursive_hashing(depth: usize) {
    println! {"Using recursive depth: {:?} times depth_per_fold in circuit (default 10 or 100, check yourself! :D)", depth};

    let iteration_count = depth;
    let root = current_dir().unwrap();

    let circuit_file = root.join("./examples/poseidon/circom/poseidon_test_nova.r1cs");
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    let witness_generator_wasm =
        root.join("./examples/poseidon/circom/poseidon_test_nova_js/poseidon_test_nova.wasm");

    let mut in_vector = vec![];
    for i in 0..depth {
        in_vector.push(gen_nth_poseidon_hash(i));
    }

    // println!("100th recursive SHA256 hash: {:?}", gen_nth_sha256_hash(100));

    use ark_bn254::Fr;
    use ark_ff::{BigInteger, One, PrimeField, Zero};
    
    let mut pre_step_in = vec![Fr::zero(), Fr::one(), Fr::from(2), Fr::from(3)];

    let pre_res: Vec<Vec<u64>> = pre_step_in
        .iter_mut()
        .map(|item| {
            let binding = item.into_bigint();
            let array: Result<[u64; 4], _> = binding.as_ref().try_into();
            let a: [u64; 4] = array.unwrap();
            a.to_vec()
        })
        .collect();

    let res: Vec<u64> = pre_res.into_iter().flatten().collect();

    println!("len res is {:?}", res.len());

    let step_in_vector = vec![0, 1, 2, 3];

    let mut private_inputs = Vec::new();
    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        // println!("len in_vector[i] is {:?}", in_vector[i].len());
        // private_input.insert("in".to_string(), json!(in_vector[i]));
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
    let start = Instant::now();
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
    let start = Instant::now();
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();
    end_timer!(timer_gen_compressed_snark);

    let timer_verify_compressed_snark = start_timer!(|| "Verify CompressedSNARK");
    let start = Instant::now();
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
    //let sha_block: u64 = args[2].parse().unwrap();

    // NOTE: Toggle here
    recursive_hashing(k);
}
