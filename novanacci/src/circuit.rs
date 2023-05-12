use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use nova_snark::traits::circuit::StepCircuit;

#[derive(Clone, Debug)]
pub struct FibonacciObject<F: PrimeField> {
    pub x: F,
    pub y: F,
    pub x_next: F,
    pub y_next: F,
}

impl<F: PrimeField> FibonacciObject<F> {
    pub fn new(num_iters: usize, x_0: &F, y_0: &F) -> (Vec<F>, Vec<Self>) {
        let res: Vec<_> = (0..num_iters)
            .scan((*x_0, *y_0), |state, _| {
                let (x, y) = *state;
                let x_next = y;
                let y_next = x + y;
                *state = (x_next, y_next);
                Some(Self {
                    x,
                    y,
                    x_next,
                    y_next,
                })
            })
            .collect();

        (vec![*x_0, *y_0], res)
    }
}
