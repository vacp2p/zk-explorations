use halo2_proofs::{
    circuit::Value,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer,
        TranscriptWriterBuffer,
    },
};

use halo2_proofs::halo2curves::{
    bn256::{Bn256, Fr, G1Affine},
    ff::Field,
};
use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength, Spec},
};

use snark_verifier::{
    halo2::{aggregation::{self, AggregationCircuit}, gen_snark_shplonk},
    GWC, SHPLONK,
};

//use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use std::convert::TryInto;
use std::marker::PhantomData;

//use criterion::{criterion_group, criterion_main, Criterion};
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

    //generate proofs for everything

    let mut transcripts = Vec::new();
    let mut proofs = Vec::new();
    //let mut snarks = Vec::new();

    //Constructs each circuit
    for i in 0..d {
        let output =
            poseidon::Hash::<_, S, ConstantLength<L>, WIDTH, RATE>::init().hash(messages[i]);

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

        transcripts.push({
            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuits[i]],
                &[&[&[messages[i + 1][0]]]],
                rng,
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        });

        proofs.push({
            let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
            create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuits[i]],
                &[&[&[messages[i + 1][0]]]],
                rng,
                &mut transcript,
            )
            .unwrap();
            transcript.finalize()
        });

        //TODO: Right here we need hashcircuit to be a standardplonk
        //snarks.push(gen_snark_shplonk(&params, &pk, circuits[i], None::<&str>));
    }

    //Aggregate
    //TODO: new pk???
    //let agg_circuit: AggregationCircuit<GWC> = aggregation::AggregationCircuit::new(&params, snarks);
    //let num_instances = agg_circuit.num_instances();
    
    //evm verify is probably overkill


    //Change to verify agg_circuit
    let accept = {
        let mut transcript = Blake2bRead::<_, G1Affine, _>::init(proofs[0].as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, _, _>(
                &params.verifier_params(),
                &pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[&[&[messages[1][0]]]],
                &mut transcript,
            )
            .unwrap(),
        )
    };

    println!("{}", accept);
}
