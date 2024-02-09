use arecibo::traits::{circuit::TrivialCircuit, snark::default_ck_hint, Group};

use arecibo::provider::PallasEngine;
use arecibo::provider::VestaEngine;
use arecibo::traits::Engine;
use pasta_curves::{pallas, vesta};

use crate::PoseidonHashChainCircuit;

pub type G1 = pallas::Point;
pub type G2 = vesta::Point;

pub type A1 = generic_array::typenum::U4;
pub type A2 = generic_array::typenum::U4;

pub type S1 = pallas::Scalar;
pub type S2 = vesta::Scalar;

pub type E1 = PallasEngine;
pub type E2 = VestaEngine;
pub type C1 = PoseidonHashChainCircuit<G1, A1>;
pub type C2 = TrivialCircuit<<E2 as Engine>::Scalar>;

pub type NovaVDFPublicParams = arecibo::PublicParams<
    E1,
    E2,
    PoseidonHashChainCircuit<G1, A1>,
    TrivialCircuit<<G2 as Group>::Scalar>,
>;

pub fn public_params() -> NovaVDFPublicParams {
    let (circuit_primary, circuit_secondary) = PoseidonHashChainCircuit::<G1, A1>::circuits();

    NovaVDFPublicParams::setup(
        &circuit_primary,
        &circuit_secondary.clone(),
        &*default_ck_hint(),
        &*default_ck_hint(),
    )
}
