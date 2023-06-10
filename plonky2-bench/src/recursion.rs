use anyhow::Result;

use plonky2::field::types::{Field, PrimeField64};
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

pub fn recursion(d: usize) -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let one = builder.one();

    let initial_hash_target = builder.add_virtual_hash();
    builder.register_public_inputs(&initial_hash_target.elements);
    let current_hash_in = builder.add_virtual_hash();
    let current_hash_out =
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(current_hash_in.elements.to_vec());
    builder.register_public_inputs(&current_hash_out.elements);
    let counter = builder.add_virtual_public_input();

    let mut common_data = common_data::<F, C, D>();
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();

    let condition = builder.add_virtual_bool_target_safe();

    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_cyclic_initial_hash = HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
    let inner_cyclic_latest_hash = HashOutTarget::try_from(&inner_cyclic_pis[4..8]).unwrap();
    let inner_cyclic_counter = inner_cyclic_pis[8];

    builder.connect_hashes(initial_hash_target, inner_cyclic_initial_hash);

    let actual_hash_in = HashOutTarget {
        elements: core::array::from_fn(|i| {
            builder.select(
                condition,
                inner_cyclic_latest_hash.elements[i],
                initial_hash_target.elements[i],
            )
        }),
    };
    builder.connect_hashes(current_hash_in, actual_hash_in);

    let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
    builder.connect(counter, new_counter);

    builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
        condition,
        &inner_cyclic_proof_with_pis,
        &common_data,
    )?;

    let cyclic_circuit_data = builder.build::<C>();

    let mut pw = PartialWitness::new();
    let initial_hash = [F::ZERO, F::ONE, F::TWO, F::from_canonical_usize(3)];
    let initial_hash_pis = initial_hash.into_iter().enumerate().collect();
    pw.set_bool_target(condition, false);
    pw.set_proof_with_pis_target::<C, D>(
        &inner_cyclic_proof_with_pis,
        &cyclic_base_proof(
            &common_data,
            &cyclic_circuit_data.verifier_only,
            initial_hash_pis,
        ),
    );
    pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
    let mut proof = cyclic_circuit_data.prove(pw)?;

    for _ in 0..d {
        let mut pw = PartialWitness::new();
        pw.set_bool_target(condition, true);
        pw.set_proof_with_pis_target(&inner_cyclic_proof_with_pis, &proof);
        pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
        proof = cyclic_circuit_data.prove(pw)?;
    }

    check_cyclic_proof_verifier_data(
        &proof,
        &cyclic_circuit_data.verifier_only,
        &cyclic_circuit_data.common,
    )?;

    let initial_hash = &proof.public_inputs[..4];
    let hash = &proof.public_inputs[4..8];
    let counter = proof.public_inputs[8];
    let expected_hash: [F; 4] = iterate_poseidon(
        initial_hash.try_into().unwrap(),
        counter.to_canonical_u64() as usize,
    );
    if hash != expected_hash {
        return Err(anyhow::Error::msg("hash was not calculated right"));
    }

    cyclic_circuit_data.verify(proof)
}

fn iterate_poseidon<F: RichField>(initial_state: [F; 4], n: usize) -> [F; 4] {
    let mut current = initial_state;
    for _ in 0..n {
        current = hash_n_to_hash_no_pad::<F, PoseidonPermutation>(&current).elements;
    }
    current
}
