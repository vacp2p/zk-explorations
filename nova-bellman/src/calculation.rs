use bellpepper::gadgets::multipack::compute_multipacking;
use ff::PrimeFieldBits;
use neptune::{poseidon::PoseidonConstants, Poseidon, poseidon_alt::hash_correct_multiple};
use nova::traits::Group;

use pasta_curves::Fq;

use crate::public_params::{A1, G1, S1};

pub fn calculate_chain_hash(mut value: Vec<<G1 as Group>::Scalar>, s: usize) -> Vec<S1> {
    let constants: PoseidonConstants<Fq, A1> =
        neptune::poseidon::PoseidonConstants::<S1, A1>::new();

    for _ in 0..s {
        let mut posiedon: Poseidon<Fq, A1> =
            neptune::Poseidon::new_with_preimage(&value, &constants);
        value = hash_correct_multiple(&mut posiedon, 4);
    }

    value
}

fn bitwise_or(value: S1, index: S1) -> S1 {
    let value_le_bits = value.to_le_bits().into_inner();

    let idx_le_bits = index.to_le_bits().into_inner();

    let mut result: [u64; 4] = [0; 4];

    for i in 0..4 {
        result[i] = value_le_bits[i] | idx_le_bits[i];
    }

    let pre_res = u64_to_bits_le(&result);

    compute_multipacking(&pre_res)[0]
}

fn u64_to_bits_le(bytes: &[u64]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&v| (0..64).map(move |i| (v >> i) & 1 == 1))
        .collect()
}
