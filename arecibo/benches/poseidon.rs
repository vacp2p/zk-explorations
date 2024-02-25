use arecibo_bellman::{calculation::calculate_chain_hash, poseidon_chain_hash_proof::NovaChainHashProof, public_params::public_params, PoseidonHashChainCircuit, TEST_SEED};
use ff::Field;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use core::time::Duration;
use criterion::*;

criterion_group! {
name = recursive_snark;
config = Criterion::default().warm_up_time(Duration::from_millis(3000));
targets = bench_recursive_snark_prove
}

criterion_main!(recursive_snark);

fn bench_recursive_snark_prove(c: &mut Criterion) {
    let cases = vec![3, 10, 100];

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let x0 = Field::random(&mut rng);
    let x1 = Field::random(&mut rng);
    let x2 = Field::random(&mut rng);
    let x3 = Field::random(&mut rng);

    

    // produce public parameters
    let pp = public_params();



  for num_steps in cases {

    let mut group = c.benchmark_group(format!(
      "Arecibo-Poseidon-num-steps-{}",
      num_steps
    ));
    group.sample_size(10);

    group.bench_function("Prove", |b| {
      b.iter(|| {
        let initial_state = vec![x0, x1, x2, x3];

        let (z0, circuits) =
        PoseidonHashChainCircuit::eval_and_make_circuits(num_steps, initial_state.clone());

        let recursive_snark =
            NovaChainHashProof::prove_recursively(&pp, &circuits, z0.clone()).unwrap();

        let zi = calculate_chain_hash(initial_state, num_steps);

        let res = recursive_snark.verify(&pp, num_steps, z0.clone(), &zi);

        if !res.is_ok() {
            dbg!(&res);
        }
        assert!(res.unwrap());
      })
    });
    group.finish();
  }
}