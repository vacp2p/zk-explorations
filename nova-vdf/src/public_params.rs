use nova::traits::{circuit::TrivialTestCircuit, Group};

use pasta_curves::{pallas, vesta};

use crate::InverseMinRootCircuit;

pub type G1 = pallas::Point;
pub type G2 = vesta::Point;

pub type S1 = pallas::Scalar;
pub type S2 = vesta::Scalar;

pub type C1 = InverseMinRootCircuit<G1>;
pub type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;

pub type NovaVDFPublicParams = nova::PublicParams<
    G1,
    G2,
    InverseMinRootCircuit<G1>,
    TrivialTestCircuit<<G2 as Group>::Scalar>,
>;

pub fn public_params(num_iters_per_step: u64) -> NovaVDFPublicParams {
    let (circuit_primary, circuit_secondary) =
        InverseMinRootCircuit::<G1>::circuits(num_iters_per_step);

    NovaVDFPublicParams::setup(circuit_primary, circuit_secondary.clone())
}
