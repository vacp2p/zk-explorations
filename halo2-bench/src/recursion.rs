use halo2_proofs::{
    circuit::Value,
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        ff::Field,
    },
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
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};

use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, Spec};

/*
use snark_verifier::{
    halo2::{
        aggregation::{self, AggregationCircuit},
        gen_snark_shplonk,
    },
    GWC, SHPLONK,
};*/

use rand::rngs::OsRng;
use snark_verifier_sdk::GWC;
use std::convert::TryInto;
use std::marker::PhantomData;

use crate::{aggregation, mycircuit::{HashCircuit, PoseidonWitness}};
//use crate::aggregation::AggregationCircuit;

const K: u32 = 7;

pub(crate) fn recursion<S, const WIDTH: usize, const RATE: usize, const L: usize>(d: usize)
where
    S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
{
    //TODO: necessary?
    assert!(d > 1, "d must be larger than 1");
    let d = d - 1;

    //TODO: COMMENT???
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

    //Original message to be hashed: [1...1]
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

    let mut proofs = Vec::new();
    let mut poseidons: Vec<PoseidonWitness<S, WIDTH, RATE, L>> = Vec::new();

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

        let proof = {
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
        };

        //TODO: delete ultimately
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

        poseidons.push(PoseidonWitness::<S, WIDTH, RATE,L> {
            instance: messages[i],
            circuit: circuits[i],
            proof: proof,
        });
    }

    //TODO working on this
    let agg_circuit: aggregation::AggregationCircuit<GWC, S, WIDTH, RATE, L> =
        aggregation::AggregationCircuit::new(&params, poseidons);

    //used for?
    //  let num_instances = agg_circuit.num_instance();

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
