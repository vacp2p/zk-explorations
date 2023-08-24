use crate::circuit::{FibonacciCircuit, FibonacciObject};
use nova_snark::{
    traits::{circuit::TrivialTestCircuit, Group},
    PublicParams, RecursiveSNARK,
};

type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;

pub fn prove_and_verify(num_steps: usize, num_iters_per_step: usize) {
    let circuit_primary = FibonacciCircuit {
        values: vec![
            FibonacciObject {
                x: <G1 as Group>::Scalar::zero(),
                y: <G1 as Group>::Scalar::zero(),
                x_next: <G1 as Group>::Scalar::zero(),
                y_next: <G1 as Group>::Scalar::zero(),
            };
            num_iters_per_step
        ],
    };

    let circuit_secondary = TrivialTestCircuit::default();

    let pp = PublicParams::<
        G1,
        G2,
        FibonacciCircuit<<G1 as Group>::Scalar>,
        TrivialTestCircuit<<G2 as Group>::Scalar>,
    >::setup(circuit_primary, circuit_secondary.clone());

    let (z0_primary, fibo_iterations) = FibonacciObject::new(
        num_iters_per_step * num_steps,
        &<G1 as Group>::Scalar::zero(),
        &<G1 as Group>::Scalar::one(),
    );
    let fibo_circuits = (0..num_steps)
        .map(|i| FibonacciCircuit {
            values: (0..num_iters_per_step)
                .map(|j| FibonacciObject {
                    x: fibo_iterations[i * num_iters_per_step + j].x,
                    y: fibo_iterations[i * num_iters_per_step + j].y,
                    x_next: fibo_iterations[i * num_iters_per_step + j].x_next,
                    y_next: fibo_iterations[i * num_iters_per_step + j].y_next,
                })
                .collect::<Vec<_>>(),
        })
        .collect::<Vec<_>>();

    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    type C1 = FibonacciCircuit<<G1 as Group>::Scalar>;
    type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;
    let mut recursive_snark: Option<RecursiveSNARK<G1, G2, C1, C2>> = None;
    for circuit_primary in fibo_circuits.iter().take(num_steps) {
        let res = RecursiveSNARK::prove_step(
            &pp,
            recursive_snark,
            circuit_primary.clone(),
            circuit_secondary.clone(),
            z0_primary.clone(),
            z0_secondary.clone(),
        );
        assert!(res.is_ok());
        recursive_snark = Some(res.unwrap());
    }

    assert!(recursive_snark.is_some());
    let recursive_snark = recursive_snark.unwrap();

    recursive_snark
        .verify(&pp, num_steps, z0_primary.clone(), z0_secondary.clone())
        .unwrap();
}
