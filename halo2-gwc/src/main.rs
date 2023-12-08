use ark_std::{end_timer, start_timer};
use halo2_curves::bn256::Fr;
use halo2_proofs::circuit::Value;
use halo2_proofs::halo2curves as halo2_curves;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use rand::RngCore;
use rand::rngs::OsRng;
use snark_verifier_sdk::halo2::{gen_srs, gen_snark_gwc};
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit},
    Snark,
};
use snark_verifier_sdk::{CircuitExt, GWC};
use std::marker::PhantomData;
use std::path::Path;

pub mod application {
    use super::halo2_curves::bn256::Fr;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
        poly::Rotation,
    };
    use ff::Field;
    use rand::RngCore;
    use snark_verifier_sdk::CircuitExt;

    use halo2_gadgets::poseidon::{
        primitives::{generate_constants, ConstantLength, Mds, Spec},
        Hash, Pow5Chip, Pow5Config,
    };
    use std::convert::TryInto;
    use std::marker::PhantomData;

    #[derive(Clone, Copy)]
    pub struct HashCircuit<S, const WIDTH: usize, const RATE: usize, const L: usize>
    where
        S: Spec<Fr, WIDTH, RATE> + Clone + Copy,
    {
        pub instance: Fr,
        pub message_arr: [Fr; L],
        pub message: Value<[Fr; L]>,
        pub _spec: PhantomData<S>,
    }

    #[derive(Debug, Clone)]
    pub struct MyConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
        input: [Column<Advice>; L],
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
                instance: Fr::ZERO,
                message_arr: [Fr::ZERO; L],
                message: Value::unknown(),
                _spec: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
            let _ = meta.instance_column();
            // // meta.enable_equality(expected);
            let partial_sbox = meta.advice_column();

            let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
            let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

            meta.enable_constant(rc_b[0]);

            Self::Config {
                input: state[..RATE].try_into().unwrap(),
                // expected,
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
            hasher.hash(layouter.namespace(|| "hash"), message)?;

            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct MySpec<const WIDTH: usize, const RATE: usize>;

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
    }

    impl CircuitExt<Fr> for StandardPlonk {
        fn num_instance(&self) -> Vec<usize> {
            vec![1]
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![vec![self.0]]
        }
    }
    impl<S, const WIDTH: usize, const RATE: usize, const L: usize> CircuitExt<Fr>
    for HashCircuit<S, WIDTH, RATE, L> 
    where
    S: Spec<Fr, WIDTH, RATE> + Copy + Clone,
    {
        fn num_instance(&self) -> Vec<usize> {
            vec![1]
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![vec![self.instance]]
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
                    region.assign_fixed(|| "", config.q_a, 0, || Value::known(-Fr::one()))?;
                    region.assign_advice(|| "", config.a, 1, || Value::known(-Fr::from(5u64)))?;
                    for (idx, column) in (1..).zip([
                        config.q_a,
                        config.q_b,
                        config.q_c,
                        config.q_ab,
                        config.constant,
                    ]) {
                        region.assign_fixed(
                            || "",
                            column,
                            1,
                            || Value::known(Fr::from(idx as u64)),
                        )?;
                    }
                    let a = region.assign_advice(|| "", config.a, 2, || Value::known(Fr::one()))?;
                    a.copy_advice(|| "", &mut region, config.b, 3)?;
                    a.copy_advice(|| "", &mut region, config.c, 4)?;

                    Ok(())
                },
            )
        }
    }
}

fn gen_application_snark(params: &ParamsKZG<Bn256>) -> Snark {
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
    gen_snark_gwc(params, &pk, circuit, None::<&str>)
}

fn main() {
    let params_app = gen_srs(8);
    let snarks = [(); 3].map(|_| gen_application_snark(&params_app));

    let params = gen_srs(23);
    let agg_circuit = AggregationCircuit::<GWC>::new(&params, snarks);
    let start0 = start_timer!(|| "gen vk & pk");
    let pk = gen_pk(
        &params,
        &agg_circuit.without_witnesses(),
        None,
    );
    end_timer!(start0);

    snark_verifier_sdk::halo2::gen_proof_gwc(
        &params,
        &pk,
        agg_circuit.clone(),
        agg_circuit.instances(),
        None,
    );
}
