//TODO: modified from???
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::{bn256::Fr, ff::Field},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

use halo2_gadgets::{poseidon::{
    primitives::{generate_constants, ConstantLength, Mds, Spec},
    Hash, Pow5Chip, Pow5Config,
}, ecc::EccInstructions};
use halo2curves::bn256::G1Affine;
use itertools::Itertools;
use snark_verifier::{pcs::{kzg::{KzgSuccinctVerifyingKey, KzgAccumulator, KzgAsVerifyingKey}, PolynomialCommitmentScheme, AccumulationScheme}, loader::{self, halo2::halo2_wrong_ecc}};
use snark_verifier_sdk::halo2::{PoseidonTranscript, POSEIDON_SPEC};
//use snark_verifier_sdk::halo2::aggregation::Halo2Loader;
use std::{convert::TryInto, rc::Rc};
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy)]
pub(crate) struct HashCircuit<S, const WIDTH: usize, const RATE: usize, const L: usize>
where
    S: Spec<Fr, WIDTH, RATE> + Clone + Copy,
{
    pub(crate) message: Value<[Fr; L]>,
    pub(crate) _spec: PhantomData<S>,
}

#[derive(Debug, Clone)]
pub(crate) struct MyConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    input: [Column<Advice>; L],
    expected: Column<Instance>,
    poseidon_config: Pow5Config<Fr, WIDTH, RATE>,
}

impl<S, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fr>
    for HashCircuit<S, WIDTH, RATE, L>
where
    S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
{
    type Config = MyConfig<WIDTH, RATE, L>;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let expected = meta.instance_column();
        meta.enable_equality(expected);
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        Self::Config {
            input: state[..RATE].try_into().unwrap(),
            expected,
            //Configure is ran here!
            poseidon_config: Pow5Chip::configure::<S>(
                meta,
                state.try_into().unwrap(),
                partial_sbox,
                rc_a.try_into().unwrap(),
                rc_b.try_into().unwrap(),
            ),
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chip = Pow5Chip::construct(config.poseidon_config.clone());

        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                let message_word = |i: usize| {
                    let value = self.message.map(|message_vals| message_vals[i]);
                    region.assign_advice(
                        || format!("load message_{}", i),
                        config.input[i],
                        0,
                        || value,
                    )
                };

                let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
                Ok(message?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        layouter.constrain_instance(output.cell(), config.expected, 0)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MySpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec<Fr, WIDTH, RATE> for MySpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fr) -> Fr {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        0
    }

    fn constants() -> (Vec<[Fr; WIDTH]>, Mds<Fr, WIDTH>, Mds<Fr, WIDTH>) {
        generate_constants::<_, Self, WIDTH, RATE>()
    }
}


#[derive(Debug, Clone)]
pub(crate) struct PoseidonWitness<S,const WIDTH: usize, const RATE: usize, const L: usize> 
where
    S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
{
    pub instance: [Fr; L],
    pub circuit: HashCircuit<S, WIDTH, RATE, L>,
    pub proof: Vec<u8>,
}











pub const LIMBS: usize = 4;
pub const BITS: usize = 68;


pub type Svk = KzgSuccinctVerifyingKey<G1Affine>;
pub type BaseFieldEccChip = halo2_wrong_ecc::BaseFieldEccChip<G1Affine, LIMBS, BITS>;
pub type Halo2Loader<'a> = loader::halo2::Halo2Loader<'a, G1Affine, BaseFieldEccChip>;

//#[allow(clippy::type_complexity)]
/// Core function used in `synthesize` to aggregate multiple `snarks`.
///  
/// Returns the assigned instances of previous snarks and the new final pair that needs to be verified in a pairing check.
/// For each previous snark, we concatenate all instances into a single vector. We return a vector of vectors,
/// one vector per snark, for convenience.
///
/// # Assumptions
/// * `snarks` is not empty
///
///TODO: modify this for our purposes because this seems to be only way
/// to do this! (PSE's comment)
pub(crate) fn aggregate<'a, //AS
S, 
const WIDTH: usize,
const RATE: usize,
const L: usize>
(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    poseidons : &[PoseidonWitness<S,WIDTH, RATE,L>], //TODO: temp
    as_proof: Value<&'_ [u8]>,
)
where
S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
/*
 -> (
    Vec<Vec<<BaseFieldEccChip as EccInstructions<'a, G1Affine>>::AssignedCell>>, // this is Vec<Vec<AssignedCell<Fr, Fr>>>, but we note what the actual trait type is for future reference
    KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
)
*/
/*
where
    AS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            VerifyingKey = Svk,
            Output = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        > + AccumulationScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
            VerifyingKey = KzgAsVerifyingKey,
        >,
        */
{
    //Verifies the array is non empty
    assert!(!poseidons.is_empty(), "trying to aggregate 0 snarks");

    let assign_instances = |instances: &[Vec<Value<Fr>>]| {
        instances
            .iter()
            .map(|instances| {
                instances
                    .iter()
                    .map(|instance| loader.assign_scalar(*instance))
                    .collect_vec()
            })
            .collect_vec()
    };

    //let mut previous_instances = Vec::with_capacity(poseidons.len());
    
    /*
    let mut accumulators = poseidons
        .iter()
        .flat_map(|poseidons: &[PoseidonWitness<L>]| {
           //TODO:
           // let protocol = snark.protocol.loaded(loader);
           // let instances = assign_instances(&snark.instances);
            
            // read the transcript and perform Fiat-Shamir
            // run through verification computation and produce the final pair `succinct`
            let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::from_spec(
                loader,
              //  snark.proof(),
                POSEIDON_SPEC.clone(),
            );
            /*
            let proof = PlonkSuccinctVerifier::<AS>::read_proof(
                svk,
                &protocol,
                &instances,
                &mut transcript,
            )
            .unwrap();
            let accumulator =
                PlonkSuccinctVerifier::<AS>::verify(svk, &protocol, &instances, &proof).unwrap();

            previous_instances.push(
                instances
                    .into_iter()
                    .flatten()
                    .map(|scalar| scalar.into_assigned())
                    .collect(),
            );

            accumulator*/
            
        });
        //.collect_vec();
    */
    
    /*
    let accumulator = if accumulators.len() > 1 {
        let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::from_spec(
            loader,
            as_proof,
            POSEIDON_SPEC.clone(),
        );
        let proof = <AS as AccumulationScheme<_, _>>::read_proof(
            &Default::default(),
            &accumulators,
            &mut transcript,
        )
        .unwrap();
        <AS as AccumulationScheme<_, _>>::verify(&Default::default(), &accumulators, &proof)
            .unwrap()
    } else {
        accumulators.pop().unwrap()
    };

    (previous_instances, accumulator)
    */
}
