use core::time::Duration;
use criterion::*;
use ff::Field;
use nova_bellman::{
    calculation::calculate_chain_hash, poseidon_chain_hash_proof::NovaChainHashProof,
    public_params::public_params, PoseidonHashChainCircuit, TEST_SEED,
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use flate2::{write::ZlibEncoder, Compression};

criterion_group! {
name = recursive_snark;
config = Criterion::default().warm_up_time(Duration::from_millis(3000));
targets = bench_recursive_snark_proof, bench_recursive_snark_verify
}

criterion_main!(recursive_snark);

fn bench_recursive_snark_proof(c: &mut Criterion) {
    let cases = vec![3, 10, 100];

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let x0 = Field::random(&mut rng);
    let x1 = Field::random(&mut rng);
    let x2 = Field::random(&mut rng);
    let x3 = Field::random(&mut rng);
    // produce public parameters
    let pp = public_params();

    for num_steps in cases {
        let mut group = c.benchmark_group(format!("Nova-Poseidon-num-steps-{}", num_steps));
        group.sample_size(10);

        group.bench_function("Prove", |b| {
            b.iter(|| {
                let initial_state = vec![x0, x1, x2, x3];

                let (z0, circuits) = PoseidonHashChainCircuit::eval_and_make_circuits(
                    num_steps,
                    initial_state.clone(),
                );

                NovaChainHashProof::prove_recursively(&pp, &circuits, z0.clone()).unwrap();
            })
        });
        group.finish();
    }
}

fn bench_recursive_snark_verify(c: &mut Criterion) {
    let cases = vec![3, 10, 100];

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let x0 = Field::random(&mut rng);
    let x1 = Field::random(&mut rng);
    let x2 = Field::random(&mut rng);
    let x3 = Field::random(&mut rng);
    // produce public parameters
    let pp = public_params();

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    for num_steps in cases {
        let mut group = c.benchmark_group(format!("Nova-Poseidon-num-steps-{}", num_steps));
        group.sample_size(10);

        let initial_state = vec![x0, x1, x2, x3];

        let (z0, circuits) =
            PoseidonHashChainCircuit::eval_and_make_circuits(num_steps, initial_state.clone());

        let recursive_snark =
            NovaChainHashProof::prove_recursively(&pp, &circuits, z0.clone()).unwrap();

        let zi = calculate_chain_hash(initial_state, num_steps);

        
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        bincode::serialize_into(&mut encoder, &recursive_snark.0).unwrap();
        let snark_encoded = encoder.finish().unwrap();
        println!(
            "Nova Bellman SNARK::len {:?} bytes for case {:?}",
            snark_encoded.len(),
            num_steps
        );
    
        group.bench_function("Verify", |b| {
            b.iter(|| {
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
