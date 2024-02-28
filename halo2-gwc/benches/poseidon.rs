use core::time::Duration;
use std::path::PathBuf;
use criterion::*;

use halo2_proofs::plonk::Circuit;
use halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2curves::bn256::Bn256;
use snark_verifier::pcs::kzg::{Gwc19, KzgAs};
use snark_verifier_sdk::halo2::{gen_proof, gen_srs};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit},
};
use snark_verifier_sdk::{CircuitExt, GWC};

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
      "Halo2-GWC-Poseidon-num-steps-{}",
      k
    ));
    group.sample_size(10);

    group.bench_function("Prove", |b| {
      b.iter(|| {
        let snarks: Vec<_> = vec![0; k].into_iter().map(|_| halo2_gwc::gen_application_snark(&params_app)).collect();

        let agg_circuit = AggregationCircuit::<GWC>::new(&params, snarks);
        let pk = gen_pk(
            &params,
            &agg_circuit.without_witnesses(),
            None,
        );

        let circuit = agg_circuit.clone();
        let instances = agg_circuit.instances();

        gen_proof::<AggregationCircuit<KzgAs<Bn256, Gwc19>>, ProverGWC<_>, VerifierGWC<_>>(&params, &pk, circuit, instances, None::<(PathBuf, PathBuf)>)
    
      })
    });
    group.finish();
  }
}