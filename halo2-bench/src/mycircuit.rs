//use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance,
    },
    poly::{
        commitment::ParamsProver,
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
use snark_verifier::{system::halo2::transcript::evm::EvmTranscript, pcs::kzg::{Gwc19, KzgAs, LimbsEncoding}, verifier};
use std::convert::TryInto;
use std::marker::PhantomData;

//From: https://github.com/zcash/halo2/blob/main/halo2_gadgets/benches/poseidon.rs
//use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

#[derive(Clone, Copy)]
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


const LIMBS: usize = 4;
const BITS: usize = 68;

type As = KzgAs<Bn256, Gwc19>;
type PlonkSuccinctVerifier = verifier::plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;
type PlonkVerifier = verifier::plonk::PlonkVerifier<As, LimbsEncoding<LIMBS, BITS>>;



mod application {
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
        poly::Rotation,
    };
    
    use halo2_proofs::halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        ff::Field,
    };
    use rand::RngCore;

    #[derive(Clone, Copy)]
    pub struct StandardPlonkConfig {
        a: Column<Advice>,
        b: Column<Advice>,
        c: Column<Advice>,
        q_a: Column<Fixed>,
        q_b: Column<Fixed>,
        q_c: Column<Fixed>,
        q_ab: Column<Fixed>,
        constant: Column<Fixed>,
        #[allow(dead_code)]
        instance: Column<Instance>,
    }

    impl StandardPlonkConfig {
        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
            let [a, b, c] = [(); 3].map(|_| meta.advice_column());
            let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
            let instance = meta.instance_column();

            [a, b, c].map(|column| meta.enable_equality(column));

            meta.create_gate(
                "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
                |meta| {
                    let [a, b, c] =
                        [a, b, c].map(|column| meta.query_advice(column, Rotation::cur()));
                    let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                        .map(|column| meta.query_fixed(column, Rotation::cur()));
                    let instance = meta.query_instance(instance, Rotation::cur());
                    Some(
                        q_a * a.clone()
                            + q_b * b.clone()
                            + q_c * c
                            + q_ab * a * b
                            + constant
                            + instance,
                    )
                },
            );

            StandardPlonkConfig {
                a,
                b,
                c,
                q_a,
                q_b,
                q_c,
                q_ab,
                constant,
                instance,
            }
        }
    }

    #[derive(Clone, Default)]
    pub struct StandardPlonk(Fr);

    impl StandardPlonk {
        pub fn rand<R: RngCore>(mut rng: R) -> Self {
            Self(Fr::from(rng.next_u32() as u64))
        }

        pub fn num_instance() -> Vec<usize> {
            vec![1]
        }

        pub fn instances(&self) -> Vec<Vec<Fr>> {
            vec![vec![self.0]]
        }
    }

    impl Circuit<Fr> for StandardPlonk {
        type Config = StandardPlonkConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "halo2_circuit_params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            meta.set_minimum_degree(4);
            StandardPlonkConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "",
                |mut region| {
                    region.assign_advice(|| "", config.a, 0, || Value::known(self.0))?;
                    region.assign_fixed(|| "", config.q_a, 0, || Value::known(-Fr::ONE))?;

                    region.assign_advice(|| "", config.a, 1, || Value::known(-Fr::from(5)))?;
                    for (idx, column) in (1..).zip([
                        config.q_a,
                        config.q_b,
                        config.q_c,
                        config.q_ab,
                        config.constant,
                    ]) {
                        region.assign_fixed(|| "", column, 1, || Value::known(Fr::from(idx)))?;
                    }

                    let a = region.assign_advice(|| "", config.a, 2, || Value::known(Fr::ONE))?;
                    a.copy_advice(|| "", &mut region, config.b, 3)?;
                    a.copy_advice(|| "", &mut region, config.c, 4)?;

                    Ok(())
                },
            )
        }
    }
}


mod aggregation {
    use super::{As, PlonkSuccinctVerifier, BITS, LIMBS};
    use itertools::Itertools;
    //use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{self, Circuit, ConstraintSystem, Error},
        poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
    };
    
    use halo2_proofs::halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        ff::Field,
    };
    use halo2_wrong_ecc::{
        integer::rns::Rns,
        maingate::{
            MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig,
            RangeInstructions, RegionCtx,
        },
        EccConfig,
    };
    //use itertools::Itertools;
    use rand::rngs::OsRng;
    use snark_verifier::{
        loader::{self, native::NativeLoader, halo2::halo2_wrong_ecc},
        pcs::{
            kzg::{KzgAccumulator, KzgSuccinctVerifyingKey, LimbsEncodingInstructions},
            AccumulationScheme, AccumulationSchemeProver,
        },
        system,
        util::arithmetic::{fe_to_limbs, PrimeField},
        verifier::{plonk::PlonkProtocol, SnarkVerifier},
    };
    use std::rc::Rc;

    const T: usize = 5;
    const RATE: usize = 4;
    const R_F: usize = 8;
    const R_P: usize = 60;

    type Svk = KzgSuccinctVerifyingKey<G1Affine>;
    type BaseFieldEccChip = halo2_wrong_ecc::BaseFieldEccChip<G1Affine, LIMBS, BITS>;
    type Halo2Loader<'a> = loader::halo2::Halo2Loader<'a, G1Affine, BaseFieldEccChip>;
    pub type PoseidonTranscript<L, S> =
        system::halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;

        
    pub struct Snark {
        protocol: PlonkProtocol<G1Affine>,
        instances: Vec<Vec<Fr>>,
        proof: Vec<u8>,
    }

    impl Snark {
        pub fn new(
            protocol: PlonkProtocol<G1Affine>,
            instances: Vec<Vec<Fr>>,
            proof: Vec<u8>,
        ) -> Self {
            Self {
                protocol,
                instances,
                proof,
            }
        }
    }

    
    impl From<Snark> for SnarkWitness {
        fn from(snark: Snark) -> Self {
            Self {
                protocol: snark.protocol,
                instances: snark
                    .instances
                    .into_iter()
                    .map(|instances| instances.into_iter().map(Value::known).collect_vec())
                    .collect(),
                proof: Value::known(snark.proof),
            }
        }
    }
    

    
    #[derive(Clone)]
    pub struct SnarkWitness {
        protocol: PlonkProtocol<G1Affine>,
        instances: Vec<Vec<Value<Fr>>>,
        proof: Value<Vec<u8>>,
    }

    impl SnarkWitness {
        fn without_witnesses(&self) -> Self {
            SnarkWitness {
                protocol: self.protocol.clone(),
                instances: self
                    .instances
                    .iter()
                    .map(|instances| vec![Value::unknown(); instances.len()])
                    .collect(),
                proof: Value::unknown(),
            }
        }

        fn proof(&self) -> Value<&[u8]> {
            self.proof.as_ref().map(Vec::as_slice)
        }
    }

    /*
    pub fn aggregate<'a>(
        svk: &Svk,
        loader: &Rc<Halo2Loader<'a>>,
        snarks: &[SnarkWitness],
        as_proof: Value<&'_ [u8]>,
    ) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
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

        let accumulators = snarks
            .iter()
            .flat_map(|snark| {
                let protocol = snark.protocol.loaded(loader);
                let instances = assign_instances(&snark.instances);
                let mut transcript =
                    PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, snark.proof());
                let proof =
                    PlonkSuccinctVerifier::read_proof(svk, &protocol, &instances, &mut transcript)
                        .unwrap();
                PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof).unwrap()
            })
            .collect_vec();

        let acccumulator = {
            let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, as_proof);
            let proof =
                As::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
            As::verify(&Default::default(), &accumulators, &proof).unwrap()
        };

        acccumulator
    }
    */

    #[derive(Clone)]
    pub struct AggregationConfig {
        main_gate_config: MainGateConfig,
        range_config: RangeConfig,
    }


    /*
    impl AggregationConfig {
        pub fn configure<F: PrimeField>(
            meta: &mut ConstraintSystem<F>,
            composition_bits: Vec<usize>,
            overflow_bits: Vec<usize>,
        ) -> Self {
            let main_gate_config = MainGate::<F>::configure(meta);
            let range_config =
                RangeChip::<F>::configure(meta, &main_gate_config, composition_bits, overflow_bits);
            AggregationConfig {
                main_gate_config,
                range_config,
            }
        }

        pub fn main_gate(&self) -> MainGate<Fr> {
            MainGate::new(self.main_gate_config.clone())
        }

        pub fn range_chip(&self) -> RangeChip<Fr> {
            RangeChip::new(self.range_config.clone())
        }

        pub fn ecc_chip(&self) -> BaseFieldEccChip {
            BaseFieldEccChip::new(EccConfig::new(
                self.range_config.clone(),
                self.main_gate_config.clone(),
            ))
        }
    }
*/

/*
    #[derive(Clone)]
    pub struct AggregationCircuit {
        svk: Svk,
        snarks: Vec<SnarkWitness>,
        instances: Vec<Fr>,
        as_proof: Value<Vec<u8>>,
    }*/


    /*
    impl AggregationCircuit {
        pub fn new(params: &ParamsKZG<Bn256>, snarks: impl IntoIterator<Item = Snark>) -> Self {
            let svk = params.get_g()[0].into();
            let snarks = snarks.into_iter().collect_vec();

            let accumulators = snarks
                .iter()
                .flat_map(|snark| {
                    let mut transcript =
                        PoseidonTranscript::<NativeLoader, _>::new(snark.proof.as_slice());
                    let proof = PlonkSuccinctVerifier::read_proof(
                        &svk,
                        &snark.protocol,
                        &snark.instances,
                        &mut transcript,
                    )
                    .unwrap();
                    PlonkSuccinctVerifier::verify(&svk, &snark.protocol, &snark.instances, &proof)
                        .unwrap()
                })
                .collect_vec();

            let (accumulator, as_proof) = {
                let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
                let accumulator =
                    As::create_proof(&Default::default(), &accumulators, &mut transcript, OsRng)
                        .unwrap();
                (accumulator, transcript.finalize())
            };

            let KzgAccumulator { lhs, rhs } = accumulator;
            let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
                .map(fe_to_limbs::<_, _, LIMBS, BITS>)
                .concat();

            Self {
                svk,
                snarks: snarks.into_iter().map_into().collect(),
                instances,
                as_proof: Value::known(as_proof),
            }
        }

        pub fn accumulator_indices() -> Vec<(usize, usize)> {
            (0..4 * LIMBS).map(|idx| (0, idx)).collect()
        }

        pub fn num_instance() -> Vec<usize> {
            vec![4 * LIMBS]
        }

        pub fn instances(&self) -> Vec<Vec<Fr>> {
            vec![self.instances.clone()]
        }

        pub fn as_proof(&self) -> Value<&[u8]> {
            self.as_proof.as_ref().map(Vec::as_slice)
        }
    }

    impl Circuit<Fr> for AggregationCircuit {
        type Config = AggregationConfig;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "halo2_circuit_params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self {
                svk: self.svk,
                snarks: self
                    .snarks
                    .iter()
                    .map(SnarkWitness::without_witnesses)
                    .collect(),
                instances: Vec::new(),
                as_proof: Value::unknown(),
            }
        }

        fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
            AggregationConfig::configure(
                meta,
                vec![BITS / LIMBS],
                Rns::<Fq, Fr, LIMBS, BITS>::construct().overflow_lengths(),
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), plonk::Error> {
            let main_gate = config.main_gate();
            let range_chip = config.range_chip();

            range_chip.load_table(&mut layouter)?;

            let accumulator_limbs = layouter.assign_region(
                || "",
                |region| {
                    let ctx = RegionCtx::new(region, 0);

                    let ecc_chip = config.ecc_chip();
                    let loader = Halo2Loader::new(ecc_chip, ctx);
                    let accumulator = aggregate(&self.svk, &loader, &self.snarks, self.as_proof());

                    let accumulator_limbs = [accumulator.lhs, accumulator.rhs]
                        .iter()
                        .map(|ec_point| {
                            loader.ecc_chip().assign_ec_point_to_limbs(
                                &mut loader.ctx_mut(),
                                ec_point.assigned(),
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?
                        .into_iter()
                        .flatten();

                    Ok(accumulator_limbs)
                },
            )?;

            for (row, limb) in accumulator_limbs.enumerate() {
                main_gate.expose_public(layouter.namespace(|| ""), limb, row)?;
            }

            Ok(())
        }
    }
    */
}
