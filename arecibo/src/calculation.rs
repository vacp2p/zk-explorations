use neptune::{poseidon::PoseidonConstants, Poseidon, poseidon_alt::hash_correct_multiple};
use arecibo::traits::Group;

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
