use core::time::Duration;
use criterion::*;

use halo2_proofs::plonk::{create_proof, verify_proof, Circuit};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_proofs::poly::VerificationStrategy;
use itertools::Itertools;
use rand::rngs::StdRng;
use rand::SeedableRng;
use snark_verifier_sdk::halo2::{gen_srs, PoseidonTranscript, POSEIDON_SPEC};
use snark_verifier_sdk::{gen_pk, halo2::aggregation::AggregationCircuit};
use snark_verifier_sdk::{CircuitExt, NativeLoader, GWC};

criterion_group! {
    name = recursive_snark;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark_proove,bench_recursive_snark_verify
}

criterion_main!(recursive_snark);

fn bench_recursive_snark_proove(c: &mut Criterion) {
    let params_app = gen_srs(8);
    let params = gen_srs(23);

    let cases = vec![3, 10, 100];

    for k in cases {
        let mut group = c.benchmark_group(format!("Halo2-GWC-Poseidon-num-steps-{}", k));
        group.sample_size(10);

        let snarks: Vec<_> = vec![0; k]
            .into_iter()
            .map(|_| halo2_gwc::gen_application_snark(&params_app))
            .collect();

        let agg_circuit = AggregationCircuit::<GWC>::new(&params, snarks);
        let pk = gen_pk(&params, &agg_circuit.without_witnesses(), None);

        let circuit = agg_circuit.clone();
        let instances = agg_circuit.instances();

        let rng = StdRng::from_entropy();
        let instances = instances.iter().map(Vec::as_slice).collect_vec();

        group.bench_function("Prove", |b| {
            b.iter(|| {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _>::from_spec(vec![], POSEIDON_SPEC.clone());

                create_proof::<_, ProverGWC<_>, _, _, _, _>(
                    &params,
                    &pk,
                    &[circuit.clone()],
                    &[&instances],
                    rng.clone(),
                    &mut transcript,
                )
                .unwrap();
                let proof = transcript.finalize();

                // validate proof before caching
                assert!({
                    let mut transcript_read = PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(
                        &proof[..],
                        POSEIDON_SPEC.clone(),
                    );
                    VerificationStrategy::<_, VerifierGWC<_>>::finalize(
                        verify_proof::<_, VerifierGWC<_>, _, _, _>(
                            params.verifier_params(),
                            pk.get_vk(),
                            AccumulatorStrategy::new(params.verifier_params()),
                            &[instances.as_slice()],
                            &mut transcript_read,
                        )
                        .unwrap(),
                    )
                });
            })
        });
        group.finish();
    }
}

fn bench_recursive_snark_verify(c: &mut Criterion) {
    let params_app = gen_srs(8);
    let params = gen_srs(23);

    let cases = vec![3, 10, 100];

    for k in cases {
        let mut group = c.benchmark_group(format!("Halo2-GWC-Poseidon-num-steps-{}", k));
        group.sample_size(10);

        let snarks: Vec<_> = vec![0; k]
            .into_iter()
            .map(|_| halo2_gwc::gen_application_snark(&params_app))
            .collect();

        let agg_circuit = AggregationCircuit::<GWC>::new(&params, snarks);
        let pk = gen_pk(&params, &agg_circuit.without_witnesses(), None);

        let circuit = agg_circuit.clone();
        let instances = agg_circuit.instances();

        let rng = StdRng::from_entropy();
        let instances = instances.iter().map(Vec::as_slice).collect_vec();

        let mut transcript =
            PoseidonTranscript::<NativeLoader, _>::from_spec(vec![], POSEIDON_SPEC.clone());

        create_proof::<_, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit.clone()],
            &[&instances],
            rng.clone(),
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();

        println!(
            "Halo2 GWC SNARK::len {:?} bytes",
            proof.len()
          );

        group.bench_function("Verify", |b| {
            b.iter(|| {
                // validate proof before caching
                assert!({
                    let mut transcript_read = PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(
                        &proof[..],
                        POSEIDON_SPEC.clone(),
                    );
                    VerificationStrategy::<_, VerifierGWC<_>>::finalize(
                        verify_proof::<_, VerifierGWC<_>, _, _, _>(
                            params.verifier_params(),
                            pk.get_vk(),
                            AccumulatorStrategy::new(params.verifier_params()),
                            &[instances.as_slice()],
                            &mut transcript_read,
                        )
                        .unwrap(),
                    )
                });
            })
        });
        group.finish();
    }
}
