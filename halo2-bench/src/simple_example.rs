use halo2_proofs::halo2curves as halo2_curves;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use rand::rngs::OsRng;
use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::halo2::gen_srs;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    Snark,
};
use snark_verifier_sdk::{CircuitExt, SHPLONK};
use std::path::Path;

mod application {
    use super::halo2_curves::bn256::Fr;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
        poly::Rotation,
    };
    use rand::RngCore;
    use snark_verifier_sdk::CircuitExt;

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
                            //+ constant //TODO: where is constant getting inputs from
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
                    //q_a a = -RANDOM
                    //This with + instance = 0.
                    let a = region.assign_advice(
                        || "",
                        config.a,
                        0,
                        || Value::known(self.0 /*+Fr::from(5u64)*/),
                    )?;
                    region.assign_fixed(|| "", config.q_a, 0, || Value::known(-Fr::one()))?;

                    //region.assign_advice(|| "", config.b, 0, || Value::known(Fr::from(5u64)))?;
                    //region.assign_fixed(|| "", config.q_b, 0, || Value::known(Fr::one()))?;

                    //let b =  region.assign_advice(|| "", config.b, 2, || Value::known(Fr::from(5u64)))?;
                    //region.assign_fixed(|| "", config.q_b, 2, || Value::known(Fr::one()))?;
                    //TODO: constant seems to be 5u64???
                    //region.assign_advice(|| "", config.a, 1, || Value::known(-Fr::from(5u64)))?;
                    //region.assign_fixed(|| "", config.constant, 1, || Value::known(Fr::from(10u64)))?;

                    //This is not used...
                    /*
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
                            0,
                            || Value::known(Fr::from(0 as u64)), //idx
                        )?;
                    }
                    */

                    //let a = region.assign_advice(|| "", config.a, 2, || Value::known(Fr::one()))?;

                    //c = offset 4, b = offset 3
                    //This is required
                    //[q_a, q_b, q_c, q_ab, constant]
                    // a.copy_advice(|| "", &mut region, config.b, 2)?;
                    // a.copy_advice(|| "", &mut region, config.c,3)?;

                    //b.copy_advice(|| "", &mut region, config.a, 0)?;
                    //b.copy_advice(|| "", &mut region, config.c,3)?;

                    // region.assign_advice(|| "", config.b, 0, || Value::known(Fr::from(5u64)))?;
                    // region.assign_fixed(|| "", config.q_b, 0, || Value::known(Fr::one()))?;

                    // region.assign_advice(|| "", config.b, 0, || Value::known(Fr::from(5u64)))?;
                    //region.assign_fixed(|| "", config.q_b, 0, || Value::known(Fr::one()))?;

                    Ok(())
                },
            )
        }
    }
}

fn gen_application_snark(params: &ParamsKZG<Bn256>) -> Snark {
    let circuit = application::StandardPlonk::rand(OsRng);

    let pk = gen_pk(params, &circuit, Some(Path::new("./examples/app.pk")));
    gen_snark_shplonk(params, &pk, circuit, None::<&str>)
}

pub fn simple_example() {
    let params_app = gen_srs(8);
    let snarks = [(); 3].map(|_| gen_application_snark(&params_app));
    
    let params = gen_srs(22);
    let agg_circuit = AggregationCircuit::<SHPLONK>::new(&params, snarks);
    
    let pk = gen_pk(
        &params,
        &agg_circuit.without_witnesses(),
        Some(Path::new("./examples/agg.pk")),
    );
  
    let num_instances = agg_circuit.num_instance();
    let instances = agg_circuit.instances();
    let proof_calldata = gen_evm_proof_shplonk(&params, &pk, agg_circuit, instances.clone());
/*
    let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit<SHPLONK>>(
        &params,
        pk.get_vk(),
        num_instances,
        Some(Path::new("./examples/StandardPlonkVerifierExample.sol")),
    );*/
    //evm_verify(deployment_code, instances, proof_calldata);*/
}
