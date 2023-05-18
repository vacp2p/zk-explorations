pub mod minroot;
pub mod error;
pub mod vdf_proof;
pub mod public_params;

pub const TEST_SEED: [u8; 16] = [42; 16];

use std::fmt::Debug;

use bellperson::{
    gadgets::{
        boolean::Boolean,
        num::{AllocatedNum, Num},
    },
    ConstraintSystem, LinearCombination, SynthesisError,
};

use ff::{Field, PrimeField};

use nova::{
    traits::{
        circuit::{StepCircuit, TrivialTestCircuit},
        Group,
    },
};

use crate::minroot::{Evaluation, MinRootVDF, State};

#[derive(Clone, Debug)]
pub struct InverseMinRootCircuit<G>
where
    G: Debug + Group,
{
    pub inverse_exponent: u64,
    pub result: Option<State<G::Scalar>>,
    pub input: Option<State<G::Scalar>>,
    pub t: u64,
}

impl<G: Group> InverseMinRootCircuit<G> {
    fn new<V: MinRootVDF<G>>(v: &Evaluation<V, G>, previous_state: State<G::Scalar>) -> Self {
        InverseMinRootCircuit {
            inverse_exponent: V::inverse_exponent(),
            result: Some(v.result),
            input: Some(previous_state),
            t: v.t,
        }
    }
}

impl<G> StepCircuit<G::Scalar> for InverseMinRootCircuit<G>
where
    G: Group,
{
    fn arity(&self) -> usize {
        3
    }

    fn synthesize<CS>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<G::Scalar>],
    ) -> Result<Vec<AllocatedNum<G::Scalar>>, SynthesisError>
    where
        CS: ConstraintSystem<G::Scalar>,
    {
        assert_eq!(self.arity(), z.len());

        let t = self.t;
        let mut x = z[0].clone();
        let mut y = z[1].clone();
        let i = z[2].clone();
        let mut i_num = Num::from(i);

        let mut final_x = x.clone();
        let mut final_y = y.clone();
        let mut final_i_num = i_num.clone();

        for j in 0..t {
            let (new_i, new_x, new_y) = inverse_round(
                &mut cs.namespace(|| format!("inverse_round_{}", j)),
                i_num,
                x,
                y,
            )?;
            final_x = new_x.clone();
            final_y = new_y.clone();
            final_i_num = new_i.clone();
            i_num = new_i;
            x = new_x;
            y = new_y;
        }

        let final_i = AllocatedNum::<G::Scalar>::alloc(&mut cs.namespace(|| "final_i"), || {
            final_i_num
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        cs.enforce(
            || "final_i matches final_i_num",
            |lc| lc + final_i.get_variable(),
            |lc| lc + CS::one(),
            |_| final_i_num.lc(G::Scalar::one()),
        );

        let res = vec![final_x, final_y, final_i];

        assert_eq!(self.arity(), z.len());

        Ok(res)
    }

    fn output(&self, z: &[G::Scalar]) -> Vec<G::Scalar> {
        let result = self.result.expect("result missing");
        let state = self.input.expect("state missing");

        debug_assert_eq!(z[0], result.x);
        debug_assert_eq!(z[1], result.y);
        debug_assert_eq!(z[2], result.i);

        vec![state.x, state.y, state.i]
    }
}

fn inverse_round<CS: ConstraintSystem<F>, F: PrimeField>(
    cs: &mut CS,
    i: Num<F>,
    x: AllocatedNum<F>,
    y: AllocatedNum<F>,
) -> Result<(Num<F>, AllocatedNum<F>, AllocatedNum<F>), SynthesisError> {
    let new_i = i
        .clone()
        .add_bool_with_coeff(CS::one(), &Boolean::Constant(true), -F::from(1));

    let new_x = AllocatedNum::<F>::alloc(&mut cs.namespace(|| "new_x"), || {
        if let (Some(y), Some(new_i)) = (y.get_value(), new_i.get_value()) {
            Ok(y - new_i)
        } else {
            Err(SynthesisError::AssignmentMissing)
        }
    })?;

    let tmp1 = x.square(&mut cs.namespace(|| "tmp1"))?;
    let tmp2 = tmp1.square(&mut cs.namespace(|| "tmp2"))?;

    let new_y = AllocatedNum::<F>::alloc(&mut cs.namespace(|| "new_y"), || {
        if let (Some(x), Some(new_x), Some(tmp2)) =
            (x.get_value(), new_x.get_value(), tmp2.get_value())
        {
            Ok((tmp2 * x) - new_x)
        } else {
            Err(SynthesisError::AssignmentMissing)
        }
    })?;

    if tmp2.get_value().is_some() {
        debug_assert_eq!(
            tmp2.get_value().ok_or(SynthesisError::AssignmentMissing)?
                * x.get_value().ok_or(SynthesisError::AssignmentMissing)?,
            new_y.get_value().ok_or(SynthesisError::AssignmentMissing)?
                + new_x.get_value().ok_or(SynthesisError::AssignmentMissing)?,
        );

        debug_assert_eq!(
            new_x.get_value().ok_or(SynthesisError::AssignmentMissing)?,
            y.get_value().ok_or(SynthesisError::AssignmentMissing)?
                - i.get_value().ok_or(SynthesisError::AssignmentMissing)?
                + F::one()
        );

        debug_assert_eq!(
            tmp2.get_value().ok_or(SynthesisError::AssignmentMissing)?
                * x.get_value().ok_or(SynthesisError::AssignmentMissing)?,
            new_y.get_value().ok_or(SynthesisError::AssignmentMissing)?
                + y.get_value().ok_or(SynthesisError::AssignmentMissing)?
                - i.get_value().ok_or(SynthesisError::AssignmentMissing)?
                + F::one()
        );
    }

    cs.enforce(
        || "new_y + new_x = (tmp2 * x)",
        |lc| lc + tmp2.get_variable(),
        |lc| lc + x.get_variable(),
        |lc| {
            lc + new_y.get_variable() + y.get_variable() - &i.lc(1.into())
                + &LinearCombination::from_coeff(CS::one(), 1.into())
        },
    );

    Ok((new_i, new_x, new_y))
}

impl<G: Group> InverseMinRootCircuit<G> {
    pub fn circuits(
        num_iters_per_step: u64,
    ) -> (InverseMinRootCircuit<G>, TrivialTestCircuit<G::Base>) {
        (
            Self::circuit_primary(num_iters_per_step),
            Self::circuit_secondary(),
        )
    }

    pub fn circuit_primary(num_iters_per_step: u64) -> InverseMinRootCircuit<G> {
        InverseMinRootCircuit {
            inverse_exponent: 5,
            result: None,
            input: None,
            t: num_iters_per_step,
        }
    }

    pub fn circuit_secondary() -> TrivialTestCircuit<G::Base> {
        TrivialTestCircuit::default()
    }

    pub fn eval_and_make_circuits<V: MinRootVDF<G>>(
        _v: V,
        num_iters_per_step: u64,
        num_steps: usize,
        initial_state: State<G::Scalar>,
    ) -> (Vec<G::Scalar>, Vec<InverseMinRootCircuit<G>>) {
        assert!(num_steps > 0);

        let (z0_primary, all_vanilla_proofs) = {
            let mut all_vanilla_proofs = Vec::with_capacity(num_steps);
            let mut state = initial_state;
            let mut z0_primary_opt = None;
            for _ in 0..num_steps {
                let (z0, proof) = Evaluation::<V, G>::eval(state, num_iters_per_step);
                state = proof.result;
                all_vanilla_proofs.push(proof);
                z0_primary_opt = Some(z0);
            }
            let z0_primary = z0_primary_opt.unwrap();
            (z0_primary, all_vanilla_proofs)
        };

        let circuits = {
            let mut previous_state = initial_state;
            let mut circuits = all_vanilla_proofs
                .iter()
                .map(|p| {
                    let rvp = Self::new(p, previous_state);
                    previous_state = rvp.result.unwrap();
                    rvp
                })
                .collect::<Vec<_>>();
            circuits.reverse();
            circuits
        };
        (z0_primary, circuits)
    }
}
