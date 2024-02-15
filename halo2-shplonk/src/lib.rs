use ark_std::{end_timer, start_timer};
use halo2_curves::bn256::Fr;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves as halo2_curves;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use rand::RngCore;
use rand::rngs::OsRng;
use snark_verifier_sdk::halo2::gen_srs;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    Snark,
};
use snark_verifier_sdk::{CircuitExt, SHPLONK};
use std::marker::PhantomData;
use std::path::Path;
use halo2_common::application;

pub fn gen_application_snark(params: &ParamsKZG<Bn256>) -> Snark {
    let mut rng = OsRng;

    let message: [Fr; 8] = (0..8)
        .map(|_| Fr::from(rng.next_u32() as u64))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let circuit = application::HashCircuit::<application::MySpec<9, 8>, 9, 8, 8> {
        instance: Fr::from(rng.next_u32() as u64),
        message_arr: message,
        message: Value::known(message),
        _spec: PhantomData,
    };

    let pk = gen_pk(params, &circuit, Some(Path::new("./examples/app.pk")));
    gen_snark_shplonk(params, &pk, circuit, None::<&str>)
}

fn main_function() {
    let params_app = gen_srs(8);
    let snarks = [(); 3].map(|_| gen_application_snark(&params_app));

    let params = gen_srs(23);
    let agg_circuit = AggregationCircuit::<SHPLONK>::new(&params, snarks);
    println!("after agg_circuit");
    let start0 = start_timer!(|| "gen vk & pk");
    let pk = gen_pk(
        &params,
        &agg_circuit.without_witnesses(),
        None,
    );
    end_timer!(start0);

    snark_verifier_sdk::halo2::gen_proof_shplonk(
        &params,
        &pk,
        agg_circuit.clone(),
        agg_circuit.instances(),
        None,
    );
}
