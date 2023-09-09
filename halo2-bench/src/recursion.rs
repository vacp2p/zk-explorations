
use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance, SingleVerifier,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, generate_constants, ConstantLength, Mds, Spec},
    Hash, Pow5Chip, Pow5Config,
};
use std::convert::TryInto;
use std::marker::PhantomData;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use crate::mycircuit;

#[derive(Debug, Clone, Copy)]
struct MySpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec<Fp, WIDTH, RATE> for MySpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fp) -> Fp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        0
    }

    fn constants() -> (Vec<[Fp; WIDTH]>, Mds<Fp, WIDTH>, Mds<Fp, WIDTH>) {
        generate_constants::<_, Self, WIDTH, RATE>()
    }
}

//const K: u32 = 7;

pub fn recursion(d: usize) -> bool {
    //criterion_group!(benches, criterion_benchmark);
    //criterion_main!(benches);
    //TODO: make recursion and bench_poseidon a single function. Currently two due to MySpec issues.
    bench_poseidon::<MySpec<3,2>, 3, 2, 4>(d)
}


fn bench_poseidon<S, const WIDTH: usize, const RATE: usize, const L : usize>(
    //name: &str,
    //c: &mut Criterion,
    d : usize,
) -> bool where
    S: Spec<Fp, WIDTH, RATE> + Copy + Clone,
{
   // let mut c:Criterion = Criterion::default();
    // Initialize the polynomial commitment parameters
    let params: Params<vesta::Affine> = Params::new(7); //Why 7?

    let empty_circuit = mycircuit::HashCircuit::<S, WIDTH, RATE, L> {
        message: Value::unknown(),
        _spec: PhantomData,
    };

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let prover_name = "prover";
    let verifier_name = "verifier";

    let mut rng = OsRng;

    let mut messages : Vec<[Fp;L]> = Vec::new();

    messages.push( (0..L)
        .map(|_| pallas::Base::random(rng))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap());

    //Fix this.
    /*
    for i in 0..d {
        messages.push(
            poseidon::Hash::<_, S, ConstantLength<L>, WIDTH, RATE>::init().hash(messages[i])
        );
    }*/

    let output = poseidon::Hash::<_, S, ConstantLength<L>, WIDTH, RATE>::init().hash(messages[0]);


    let circuit = mycircuit::HashCircuit::<S, WIDTH, RATE, L> {
        message: Value::known(messages[0]),
        _spec: PhantomData,
    };

    // Create a proof
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[&[output]]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    
    verify_proof( &params, pk.get_vk(), strategy, &[&[&[output]]], &mut transcript).is_ok()

}
