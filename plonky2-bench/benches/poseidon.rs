use core::time::Duration;
use criterion::*;
use plonky2_bench::recursion::recursion;

criterion_group! {
    name = recursive_snark;
    config = Criterion::default().warm_up_time(Duration::from_millis(3000));
    targets = bench_recursive_snark
}

criterion_main!(recursive_snark);

fn bench_recursive_snark(c: &mut Criterion) {
    let cases = vec![3, 10, 100];

    for k in cases {
        let mut group = c.benchmark_group(format!("Plonky2-Poseidon-num-steps-{}", k));
        group.sample_size(10);

        group.bench_function("Prove", |b| {
            b.iter(|| {
                recursion(k);
            })
        });
        group.finish();
    }
}
