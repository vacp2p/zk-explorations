#[cfg(test)]
mod test {
    use crate::calculation::calculate_chain_hash;
    use crate::poseidon_chain_hash_proof::NovaChainHashProof;
    use crate::public_params::public_params;
    use crate::{PoseidonHashChainCircuit, TEST_SEED};

    use ff::Field;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_nova_proof_single() {
        test_nova_proof_aux(1);
    }

    #[test]
    fn test_nova_proof_3() {
        test_nova_proof_aux(3);
    }

    #[test]
    fn test_nova_proof_10() {
        test_nova_proof_aux(10);
    }

    #[test]
    fn test_nova_proof_100() {
        test_nova_proof_aux(100);
    }

    fn test_nova_proof_aux(num_steps: usize) {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        let x0 = Field::random(&mut rng);
        let x1 = Field::random(&mut rng);
        let x2 = Field::random(&mut rng);
        let x3 = Field::random(&mut rng);

        let initial_state = vec![x0, x1, x2, x3];

        // produce public parameters
        let pp = public_params();

        let (z0, circuits) =
            PoseidonHashChainCircuit::eval_and_make_circuits(num_steps, initial_state.clone());

        let recursive_snark =
            NovaChainHashProof::prove_recursively(&pp, &circuits, z0.clone()).unwrap();

        let zi = calculate_chain_hash(initial_state, num_steps);

        let res = recursive_snark.verify(&pp, num_steps, z0.clone(), &zi);

        if !res.is_ok() {
            dbg!(&res);
        }
        assert!(res.unwrap());
    }
}
