//use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance,
    },
    poly::{
        commitment::ParamsProver,
        //Next we replace ipa with kzg!
        /*ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
            strategy::SingleStrategy,
        },*/
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::{AccumulatorStrategy, SingleStrategy},
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWrite,
        TranscriptWriterBuffer,
    },
};

use halo2_proofs::halo2curves::{
    bn256::{Bn256, Fr, G1Affine},
    ff::Field,
};

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, generate_constants, ConstantLength, Mds, Spec},
    Hash, Pow5Chip, Pow5Config,
};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use std::convert::TryInto;
use std::marker::PhantomData;

use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use crate::mycircuit::HashCircuit;

const K: u32 = 7;

pub(crate) fn recursion<S, const WIDTH: usize, const RATE: usize, const L: usize>(d: usize)
where
    S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
{
    assert!(d > 1, "d must be larger than 1");
    let d = d - 1;

    let empty_circuit = HashCircuit::<S, WIDTH, RATE, L> {
        message: Value::unknown(),
        _spec: PhantomData,
    };

    let rng = OsRng;

    let params = ParamsKZG::<Bn256>::setup(K, OsRng);

    let vk = keygen_vk(&params, &empty_circuit).unwrap();
    let pk = keygen_pk(&params, vk, &empty_circuit).unwrap();

    let mut messages: Vec<[Fr; L]> = Vec::new();
    let mut circuits: Vec<HashCircuit<S, WIDTH, RATE, L>> = Vec::new();
    let proofs: Vec<Vec<u8>> = Vec::new();

    messages.push(
        (0..L)
            .map(|_| Fr::ONE)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );

    circuits.push(HashCircuit::<S, WIDTH, RATE, L> {
        message: Value::known(messages[0]),
        _spec: PhantomData,
    });

    let mut output: Fr;

    for i in 0..d {
        output = poseidon::Hash::<_, S, ConstantLength<L>, WIDTH, RATE>::init().hash(messages[i]);

        messages.push(
            (0..L)
                .map(|_| output)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        circuits.push(HashCircuit::<S, WIDTH, RATE, L> {
            message: Value::known(messages[i]),
            _spec: PhantomData,
        });
    }

    /*
    for j in [0..d] {
        proofs.push({
            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuits[i]],
                &[&[&[messages[i][0]]]],
                rng,
                &mut transcripts[i],
            )
            .unwrap();
            transcript.finalize()
        });
    }*/

    let proof: Vec<u8> = {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuits[0]],
            &[&[&[messages[1][0]]]],
            rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = Blake2bRead::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, _, _>(
                &params.verifier_params(),
                &pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[&[&messages[0]]],
                &mut transcript,
            )
            .unwrap(),
        )
    };

    println!("{}", accept);
}
