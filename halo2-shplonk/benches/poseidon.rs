use core::time::Duration;
use std::fs;
use std::path::{Path, PathBuf};
use criterion::*;

use halo2_gadgets::sinsemilla::primitives::C;
use halo2_proofs::plonk::{create_proof, verify_proof, Circuit, Instance};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
use halo2_proofs::poly::VerificationStrategy;
use halo2curves::bn256::Bn256;
use itertools::Itertools;
use rand::rngs::StdRng;
use rand::SeedableRng;
use snark_verifier::pcs::kzg::{Bdfg21, KzgAs};
use snark_verifier_sdk::halo2::{gen_proof, gen_srs, PoseidonTranscript, POSEIDON_SPEC};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit},
};
use snark_verifier_sdk::{read_instances, write_instances, CircuitExt, NativeLoader, SHPLONK};

criterion_group! {
    name = recursive_snark;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark
}
    
criterion_main!(recursive_snark);

fn bench_recursive_snark(c: &mut Criterion) {
  let params_app = gen_srs(8);
  let params = gen_srs(23);

  let cases = vec![3, 10, 100];

  for k in cases {

    let mut group = c.benchmark_group(format!(
      "Halo2-SHPLONK-Poseidon-num-steps-{}",
      k
    ));
    group.sample_size(10);

    let snarks: Vec<_> = vec![0; k].into_iter().map(|_| halo2_shplonk::gen_application_snark(&params_app)).collect();

        let agg_circuit = AggregationCircuit::<SHPLONK>::new(&params, snarks);
        let pk = gen_pk(
            &params,
            &agg_circuit.without_witnesses(),
            None,
        );

    let circuit = agg_circuit.clone();
    let instances = agg_circuit.instances();

    group.bench_function("Prove", |b| {
      b.iter(|| {
        
  
      let instances = instances.iter().map(Vec::as_slice).collect_vec();
  
  
  
      let mut transcript =
          PoseidonTranscript::<NativeLoader, _>::from_spec(vec![], POSEIDON_SPEC.clone());
      let rng = StdRng::from_entropy();
      create_proof::<_, ProverSHPLONK<_>, _, _, _, _>(&params, &pk, &[circuit.clone()], &[&instances], rng, &mut transcript)
          .unwrap();
      let proof = transcript.finalize();
  
  
      // validate proof before caching
      assert!({
          let mut transcript_read =
              PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&proof[..], POSEIDON_SPEC.clone());
          VerificationStrategy::<_, VerifierSHPLONK<_>>::finalize(
              verify_proof::<_, VerifierSHPLONK<_>, _, _, _>(
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