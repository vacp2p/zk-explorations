use nova::traits::{circuit::TrivialTestCircuit, Group};

use pasta_curves::{pallas, vesta};

use crate::PoseidonHashChainCircuit;

pub type G1 = pallas::Point;
pub type G2 = vesta::Point;

pub type A1 = generic_array::typenum::U4;
pub type A2 = generic_array::typenum::U4;

pub type S1 = pallas::Scalar;
pub type S2 = vesta::Scalar;

pub type C1 = PoseidonHashChainCircuit<G1, A1>;
pub type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;

pub type NovaVDFPublicParams = nova::PublicParams<
    G1,
    G2,
    PoseidonHashChainCircuit<G1, A1>,
    TrivialTestCircuit<<G2 as Group>::Scalar>,
>;

pub fn public_params() -> NovaVDFPublicParams {
    let (circuit_primary, circuit_secondary) = PoseidonHashChainCircuit::<G1, A1>::circuits();

    NovaVDFPublicParams::setup(&circuit_primary, &circuit_secondary.clone())
}
