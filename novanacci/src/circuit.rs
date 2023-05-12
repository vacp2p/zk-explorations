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
