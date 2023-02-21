use halo2_proofs::circuit:: Value;

mod circuit;

use circuit::MyCircuit;
use halo2_proofs::{dev::MockProver, pasta::Fp};

fn main() {
    let k = 6;

    let constant = Fp::from(7);
    let a = Fp::from(2);
    let b = Fp::from(3);
    let c = constant * a * a * a * b * b * b;

    let circuit = MyCircuit {
        constant,
        a: Value::known(a),
        b: Value::known(b),
    };

    let mut public_inputs = vec![c];

    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail
    public_inputs[0] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err());
}
