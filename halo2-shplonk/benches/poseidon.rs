use core::time::Duration;
use criterion::*;

use halo2_proofs::plonk::Circuit;
use snark_verifier_sdk::halo2::{gen_srs};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit},
};
use snark_verifier_sdk::{CircuitExt, SHPLONK};

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

    group.bench_function("Prove", |b| {
      b.iter(|| {
        let snarks: Vec<_> = vec![0; k].into_iter().map(|_| halo2_shplonk::gen_application_snark(&params_app)).collect();

        let agg_circuit = AggregationCircuit::<SHPLONK>::new(&params, snarks);
        let pk = gen_pk(
            &params,
            &agg_circuit.without_witnesses(),
            None,
        );

        snark_verifier_sdk::halo2::gen_proof_shplonk(
          &params,
          &pk,
          agg_circuit.clone(),
          agg_circuit.instances(),
          None,
      );
    
      })
    });
    group.finish();
  }
}