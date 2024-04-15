use crate::{
    error::Error,
    public_params::{NovaVDFPublicParams, A1, C1, C2, G1, G2, S1, S2},
    PoseidonHashChainCircuit,
};

use nova::{errors::NovaError, traits::Group, RecursiveSNARK};

pub struct NovaChainHashProof(pub RecursiveSNARK<G1, G2, C1, C2>);

impl NovaChainHashProof {
    pub fn prove_recursively(
        pp: &NovaVDFPublicParams,
        circuits: &[PoseidonHashChainCircuit<G1, A1>],
        z0: Vec<S1>,
    ) -> Result<Self, Error> {
        let z0_primary = z0;
        let z0_secondary = Self::z0_secondary();

        let (_circuit_primary, circuit_secondary) = PoseidonHashChainCircuit::<G1, A1>::circuits();

        // produce a recursive SNARK
        let mut recursive_snark: Option<RecursiveSNARK<G1, G2, C1, C2>> = None;

        for circuit_primary in circuits.iter() {
            if let Some(mut rs) = recursive_snark {
                let res = rs
                    .prove_step(
                        pp,
                        &circuit_primary.clone(),
                        &circuit_secondary.clone(),
                        z0_primary.clone(),
                        z0_secondary.clone(),
                    )
                    .map_err(Error::Nova);
                if res.is_err() {
                    dbg!(&res);
                }
                assert!(res.is_ok());
                recursive_snark = Some(rs);
            } else {
                let mut rs = RecursiveSNARK::new(
                    pp,
                    &circuit_primary.clone(),
                    &circuit_secondary.clone(),
                    z0_primary.clone(),
                    z0_secondary.clone(),
                );
                let res = rs
                    .prove_step(
                        pp,
                        &circuit_primary.clone(),
                        &circuit_secondary.clone(),
                        z0_primary.clone(),
                        z0_secondary.clone(),
                    )
                    .map_err(Error::Nova);
                if res.is_err() {
                    dbg!(&res);
                }
                assert!(res.is_ok());
                recursive_snark = Some(rs);
            }
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

        let (zi_primary_verified, zi_secondary_verified) =
            self.0.verify(pp, num_steps, &z0_primary, &z0_secondary)?;

        Ok(zi_primary == zi_primary_verified && zi_secondary == zi_secondary_verified)
    }

    fn z0_secondary() -> Vec<S2> {
        vec![<G2 as Group>::Scalar::zero()]
    }
}
