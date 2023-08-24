use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use nova_snark::traits::circuit::StepCircuit;

#[warn(unused_imports)]
use crate::prove_verify::prove_and_verify;

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

#[derive(Clone, Debug)]
pub struct FibonacciCircuit<F: PrimeField> {
    pub values: Vec<FibonacciObject<F>>,
}

impl<F: PrimeField> StepCircuit<F> for FibonacciCircuit<F> {
    fn arity(&self) -> usize {
        2
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let mut z_out: Result<Vec<AllocatedNum<F>>, SynthesisError> =
            Err(SynthesisError::AssignmentMissing);

        let x_0 = z[0].clone();
        let y_0 = z[1].clone();

        let mut x = x_0;
        let mut y = y_0;
        for i in 0..self.values.len() {
            let y_next = AllocatedNum::alloc(cs.namespace(|| format!("y_next_{i}")), || {
                Ok(self.values[i].y_next)
            })?;
            let dummy = AllocatedNum::alloc(cs.namespace(|| format!("one_{i}")), || Ok(F::from(1)))?;

            cs.enforce(
                || format!("y_next_{i} * 1 = x_{i} + y_{i}"),
                |lc| lc + y_next.get_variable(),
                |lc| lc + dummy.get_variable(),
                |lc| lc + x.get_variable() + y.get_variable(),
            );
            if i == self.values.len() - 1 {
                z_out = Ok(vec![y.clone(), y_next.clone()]);
            }

            x = y;
            y = y_next;
        }
        z_out
    }

    fn output(&self, z: &[F]) -> Vec<F> {
        debug_assert_eq!(z[0], self.values[0].x);
        debug_assert_eq!(z[1], self.values[0].y);

        vec![
            self.values[self.values.len() - 1].x_next,
            self.values[self.values.len() - 1].y_next,
        ]
    }
}

#[test]
fn test_basic() {
    prove_and_verify(4, 10);
}

#[test]
fn test_medium() {
    prove_and_verify(5, 50);
}

#[test]
fn test_bigger() {
    prove_and_verify(4, 100);
}

#[test]
fn test_huge() {
    prove_and_verify(10, 4096);
}
