use core::time::Duration;
use criterion::*;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::{
    field::types::PrimeField64,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
    recursion::{
        cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::cyclic_base_proof,
    },
};
use plonky2_bench::recursion::check_hash_value;
use plonky2_bench::recursion::{init, iterate_poseidon, C, D, F};
use plonky2_field::types::Field;

criterion_group! {
    name = recursive_snark;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark_proove,bench_recursive_snark_verify
}

criterion_main!(recursive_snark);

fn bench_recursive_snark_proove(c: &mut Criterion) {
    let cases = vec![3, 10, 100];

    for d in cases {
        let mut group = c.benchmark_group(format!("Plonky2-Poseidon-num-steps-{}", d));
        group.sample_size(10);

        let d = d - 1;

        let (builder, common_data, condition, inner_cyclic_proof_with_pis, verifier_data_target) =
            init(d).unwrap();

        let cyclic_circuit_data = builder.build::<C>();

        // initial witness
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

        let mut proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, D> =
            cyclic_circuit_data.prove(pw.clone()).unwrap();

        group.bench_function("Prove", |b| {
            b.iter(|| {
                proof = cyclic_circuit_data.prove(pw.clone()).unwrap();

                // wire up consecutive inputs and outputs
                for _ in 0..d {
                    let mut pw = PartialWitness::new();
                    pw.set_bool_target(condition, true);
                    pw.set_proof_with_pis_target(&inner_cyclic_proof_with_pis, &proof);
                    pw.set_verifier_data_target(
                        &verifier_data_target,
                        &cyclic_circuit_data.verifier_only,
                    );
                    proof = cyclic_circuit_data.prove(pw).unwrap();
                }

                check_cyclic_proof_verifier_data(
                    &proof,
                    &cyclic_circuit_data.verifier_only,
                    &cyclic_circuit_data.common,
                )
                .unwrap();
            })
        });

        let num_constr: usize = common_data
            .gates
            .iter()
            .map(|gate| gate.0.num_constraints())
            .sum();

        println!("");
        println!("Number of constraints: {}", num_constr);

        check_hash_value(&proof).unwrap();

        group.finish();
    }
}

fn bench_recursive_snark_verify(c: &mut Criterion) {
    let cases = vec![3, 10, 100];

    for d in cases {
        let mut group = c.benchmark_group(format!("Plonky2-Poseidon-num-steps-{}", d));
        group.sample_size(10);

        let d = d - 1;

        let (builder, common_data, condition, inner_cyclic_proof_with_pis, verifier_data_target) =
            init(d).unwrap();

        let cyclic_circuit_data = builder.build::<C>();

        // initial witness
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

        let mut proof = cyclic_circuit_data.prove(pw.clone()).unwrap();

        // wire up consecutive inputs and outputs
        for _ in 0..d {
            let mut pw = PartialWitness::new();
            pw.set_bool_target(condition, true);
            pw.set_proof_with_pis_target(&inner_cyclic_proof_with_pis, &proof);
            pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
            proof = cyclic_circuit_data.prove(pw).unwrap();
        }

        check_cyclic_proof_verifier_data(
            &proof,
            &cyclic_circuit_data.verifier_only,
            &cyclic_circuit_data.common,
        )
        .unwrap();

        let num_constr: usize = common_data
            .gates
            .iter()
            .map(|gate| gate.0.num_constraints())
            .sum();

        println!("Number of constraints: {}", num_constr);

        check_hash_value(&proof).unwrap();

        group.bench_function("Verify", |b| {
            b.iter(|| cyclic_circuit_data.verify(proof.clone()))
        });

        group.finish();
    }
}
