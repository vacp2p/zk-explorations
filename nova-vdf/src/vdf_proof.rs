
use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem};

use crate::{error::Error, public_params::{NovaVDFPublicParams, G1, G2, C1, C2, S1, S2}, InverseMinRootCircuit};

use nova::{
    errors::NovaError,
    traits::{Group, circuit::StepCircuit},
    RecursiveSNARK,
};

pub struct NovaVDFProof(RecursiveSNARK<G1, G2, C1, C2>);

impl NovaVDFProof {
    pub fn prove_recursively(
        pp: &NovaVDFPublicParams,
        circuits: &[InverseMinRootCircuit<G1>],
        num_iters_per_step: u64,
        z0: Vec<S1>,
    ) -> Result<Self, Error> {
        let debug = false;
        let z0_primary = z0;
        let z0_secondary = Self::z0_secondary();

        let (_circuit_primary, circuit_secondary) =
            InverseMinRootCircuit::<G1>::circuits(num_iters_per_step);

        // produce a recursive SNARK
        let mut recursive_snark: Option<RecursiveSNARK<G1, G2, C1, C2>> = None;

        for (i, circuit_primary) in circuits.iter().enumerate() {
            if debug {
                // For debugging purposes, synthesize the circuit and check that the constraint system is satisfied.
                use bellperson::util_cs::test_cs::TestConstraintSystem;
                let mut cs = TestConstraintSystem::<<G1 as Group>::Scalar>::new();

                let r = circuit_primary.result.unwrap();

                let zi_allocated = vec![
                    AllocatedNum::alloc(cs.namespace(|| format!("z{}_1", i)), || Ok(r.x))
                        .map_err(Error::Synthesis)?,
                    AllocatedNum::alloc(cs.namespace(|| format!("z{}_2", i)), || Ok(r.y))
                        .map_err(Error::Synthesis)?,
                    AllocatedNum::alloc(cs.namespace(|| format!("z{}_0", i)), || Ok(r.i))
                        .map_err(Error::Synthesis)?,
                ];

                circuit_primary
                    .synthesize(&mut cs, zi_allocated.as_slice())
                    .map_err(Error::Synthesis)?;

                assert!(cs.is_satisfied());
            }

            let res = RecursiveSNARK::prove_step(
                pp,
                recursive_snark,
                circuit_primary.clone(),
                circuit_secondary.clone(),
                z0_primary.clone(),
                z0_secondary.clone(),
            );
            if res.is_err() {
                dbg!(&res);
            }
            assert!(res.is_ok());
            recursive_snark = Some(res.map_err(Error::Nova)?);
        }

        Ok(Self(recursive_snark.unwrap()))
    }

    pub fn verify(
        &self,
        pp: &NovaVDFPublicParams,
        num_steps: usize,
        z0: Vec<S1>,
        zi: &[S1],
    ) -> Result<bool, NovaError> {
        let (z0_primary, zi_primary) = (z0, zi);
        let z0_secondary = Self::z0_secondary();
        let zi_secondary = z0_secondary.clone();

        let (zi_primary_verified, zi_secondary_verified) = self.0.verify(pp, num_steps, z0_primary, z0_secondary)?;

        Ok(zi_primary == zi_primary_verified && zi_secondary == zi_secondary_verified)
    }

    fn z0_secondary() -> Vec<S2> {
        vec![<G2 as Group>::Scalar::zero()]
    }
}