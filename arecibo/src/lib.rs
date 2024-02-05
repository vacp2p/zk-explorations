pub mod calculation;
pub mod error;
pub mod poseidon_chain_hash_proof;
pub mod public_params;
pub mod tests;

pub const TEST_SEED: [u8; 16] = [42; 16];

use std::{fmt::Debug, marker::PhantomData};

use arecibo::{
    traits::{
      circuit::{StepCircuit, TrivialCircuit},
      Group,
    },
  };
  use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};

use neptune::{circuit::poseidon_hash_multiple, poseidon::PoseidonConstants, Arity};

#[derive(Clone, Debug)]
pub struct PoseidonHashChainCircuit<G, A>
where
    G: Debug + Group,
    A: Arity<G::Scalar>,
{
    _a: PhantomData<A>,
    _g: PhantomData<G>,
}

impl<G: Group, A: Arity<G::Scalar>> PoseidonHashChainCircuit<G, A> {
    fn new() -> Self {
        PoseidonHashChainCircuit {
            _a: PhantomData::<A>,
            _g: PhantomData::<G>,
        }
    }
}

impl<G, A> StepCircuit<G::Scalar> for PoseidonHashChainCircuit<G, A>
where
    G: Group,
    A: Arity<G::Scalar> + std::marker::Send + std::marker::Sync,
{
    fn arity(&self) -> usize {
        4
    }

    fn synthesize<CS>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<<G as Group>::Scalar>],
    ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError>
    where
        CS: ConstraintSystem<G::Scalar>,
    {
        assert_eq!(self.arity(), z.len());

        let x0 = z[0].clone();
        let x1 = z[1].clone();
        let x2 = z[2].clone();
        let x3 = z[3].clone();

        let constants = PoseidonConstants::<G::Scalar, A>::new();

        let res = poseidon_hash_multiple(
            cs,
            vec![x0, x1, x2, x3],
            &constants,
            4,
        )
        .unwrap();

        assert_eq!(self.arity(), res.len());

        Ok(res)
    }
}

impl<G: Group, A: Arity<G::Scalar>> PoseidonHashChainCircuit<G, A> {
    pub fn circuits() -> (PoseidonHashChainCircuit<G, A>, TrivialCircuit<G::Base>) {
        (Self::circuit_primary(), Self::circuit_secondary())
    }

    pub fn circuit_primary() -> PoseidonHashChainCircuit<G, A> {
        PoseidonHashChainCircuit {
            _a: PhantomData::<A>,
            _g: PhantomData::<G>,
        }
    }

    pub fn circuit_secondary() -> TrivialCircuit<G::Base> {
        TrivialCircuit::default()
    }

    pub fn eval_and_make_circuits(
        num_steps: usize,
        initial_state: Vec<G::Scalar>,
    ) -> (Vec<G::Scalar>, Vec<PoseidonHashChainCircuit<G, A>>) {
        assert!(num_steps > 0);

        let z0_primary = initial_state;

        let circuits = {
            let circuits = (1..(num_steps + 1))
                .map(|_| {
                    let rvp = Self::new();
                    rvp
                })
                .collect::<Vec<_>>();
            circuits
        };
        (z0_primary, circuits)
    }
}
