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


use rand_chacha::ChaCha20Rng;



use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength, Spec};

/*
use snark_verifier::{
    halo2::{
        aggregation::{self, AggregationCircuit},
        gen_snark_shplonk,
    },
    GWC, SHPLONK,
};*/

use halo2curves::CurveAffine;
use rand::{rngs::OsRng, SeedableRng};
use snark_verifier_sdk::GWC;
use std::{convert::TryInto, fs::{File, self}, env::var, io::{BufReader, BufWriter}};
use std::marker::PhantomData;

use crate::mycircuit::{HashCircuit, PoseidonWitness};
//use crate::aggregation;

// The following two functions are from PSE's snark-verifier-sdk/src/halo2.rs
// Importantly, these generate the srs of desired sizes once, and saves to file.
// |srs| = 22 is quite time consuming to generate.
pub fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    read_or_create_srs::<G1Affine, _>(k, |k| {
        ParamsKZG::<Bn256>::setup(k, ChaCha20Rng::from_seed(Default::default()))
    })
}

pub fn read_or_create_srs<'a, C: CurveAffine, P: ParamsProver<'a, C>>(
    k: u32,
    setup: impl Fn(u32) -> P,
) -> P {
    let dir = var("PARAMS_DIR").unwrap_or_else(|_| "./params".to_string());
    let path = format!("{dir}/kzg_bn254_{k}.srs");
    match File::open(path.as_str()) {
        Ok(f) => {
            #[cfg(feature = "display")]
            println!("read params from {path}");
            let mut reader = BufReader::new(f);
            P::read(&mut reader).unwrap()
        }
        Err(_) => {
            #[cfg(feature = "display")]
            println!("creating params for {k}");
            fs::create_dir_all(dir).unwrap();
            let params = setup(k);
            params
                .write(&mut BufWriter::new(File::create(path).unwrap()))
                .unwrap();
            params
        }
    }
}


//TODO: comment
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

    let params = gen_srs(8);
    let params_agg = gen_srs(22);


    //let vk = keygen_vk(&params, &empty_circuit).unwrap();
    //let pk = keygen_pk(&params, vk, &empty_circuit).unwrap();

    /*
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
    */


   // let mut proofs = Vec::new();
   // let mut poseidons: Vec<PoseidonWitness<S, WIDTH, RATE, L>> = Vec::new();


/*
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
*/

    /*
    //TODO working on this
    let agg_circuit: aggregation::AggregationCircuit<GWC, S, WIDTH, RATE, L> =
        aggregation::AggregationCircuit::new(&params, poseidons);
*/
    //used for?
    //  let num_instances = agg_circuit.num_instance();

    //evm verify is probably overkill

    //Change to verify agg_circuit
    /*
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

    println!("{}", accept);*/
}
