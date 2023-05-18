#[cfg(test)]
mod test {
    use super::*;
    use crate::minroot::{PallasVDF, State};
    use crate::TEST_SEED;
    use crate::public_params::{S1, G1};
    use crate::vdf_proof::NovaVDFProof;
    use crate::public_params::public_params;

    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_nova_proof() {
        test_nova_proof_aux::<PallasVDF>(5, 3);
    }

    fn test_nova_proof_aux<V: MinRootVDF<G1> + PartialEq>(
        num_iters_per_step: u64,
        num_steps: usize,
    ) {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        type F = S1;
        type G = G1;

        let x = Field::random(&mut rng);
        let y = F::zero();
        let initial_i = F::one();

        let initial_state = State { x, y, i: initial_i };
        let zi = vec![x, y, initial_i];

        // produce public parameters
        let pp = public_params(num_iters_per_step);

        let (z0, circuits) = InverseMinRootCircuit::eval_and_make_circuits(
            V::new(),
            num_iters_per_step,
            num_steps,
            initial_state,
        );

        let recursive_snark =
            NovaVDFProof::prove_recursively(&pp, &circuits, num_iters_per_step, z0.clone())
                .unwrap();

        let res = recursive_snark.verify(&pp, num_steps, z0.clone(), &zi);

        if !res.is_ok() {
            dbg!(&res);
        }
        assert!(res.unwrap());
    }
}
