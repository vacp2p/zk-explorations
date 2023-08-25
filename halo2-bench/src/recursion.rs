use anyhow::Result;

use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::hashing::hash_n_to_hash_no_pad;
use plonky2::hash::poseidon::{PoseidonHash, PoseidonPermutation};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use crate::common::common_data;

pub fn recursion(d: usize) {//-> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    //TODO: temp
    assert!(d > 0, "recursive error");
    /*
    if d == 0 {
        return Err(anyhow::Error::msg("recursion count has to be at least 1"));
    }*/

    let initial_hash = [F::ZERO, F::ONE, F::TWO, F::from_canonical_usize(3)];
    let expected_hash: [F; 4] = iterate_poseidon(
        initial_hash,
        d,
    );

    let d = d - 1;
}

fn iterate_poseidon<F: RichField>(initial_state: [F; 4], n: usize) -> [F; 4] {
    let mut current = initial_state;
    for _ in 0..n {
        current = hash_n_to_hash_no_pad::<F, PoseidonPermutation>(&current).elements;
    }
    current
}
