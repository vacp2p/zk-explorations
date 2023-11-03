use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::field::types::Sample;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::timing::TimingTree;
use poseidon_starky::columns::STATE_SIZE;
use poseidon_starky::generation::{generate_poseidon_trace, Row};
use poseidon_starky::stark::{trace_to_poly_values, PoseidonStark};
use starky::config::StarkConfig;
use starky::prover::prove;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type S = PoseidonStark<F, D>;

fn bench_poseidon_starky(c: &mut Criterion) {
    let mut config = StarkConfig::standard_fast_config();
    config.fri_config.cap_height = 0;
    config.fri_config.rate_bits = 3; // to meet the constraint degree bound

    let num_rows = 1 << 10;
    let mut step_rows = Vec::with_capacity(num_rows);
    for _ in 0..num_rows {
        let preimage = (0..STATE_SIZE).map(|_| F::rand()).collect::<Vec<_>>();
        step_rows.push(Row {
            preimage: preimage.try_into().unwrap(),
        });
    }

    let stark = S::default();
    let trace = generate_poseidon_trace(&step_rows);
    let trace_poly_values = trace_to_poly_values(trace);

    let mut timing = TimingTree::default();
    c.bench_function("poseidon_starky", |b| {
        b.iter_batched(
            || trace_poly_values.clone(),
            |trace_poly_values| {
                prove::<F, C, S, D>(stark, &config, trace_poly_values, [], &mut timing).unwrap();
            },
            criterion::BatchSize::SmallInput,
        );
    });
}


criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(std::time::Duration::from_secs(20)).sample_size(50);
    targets = bench_poseidon_starky
}
criterion_main!(benches);
