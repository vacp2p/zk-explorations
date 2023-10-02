pub mod aggregation;
pub mod mycircuit;
pub mod recursion;

use mycircuit::MySpec;

fn main() {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const L: usize = 2;

    let d: usize = 2; //Number of times Poseidon hash is applied.

    //Necessary for the Poseidon circuit (Pow5Chip) from halo2_gadget/src/poseidon/pow5.rs (line 48)
    //Note: halo2_gadget is PSE's (the same(?) as zcash)
    assert_eq!(RATE, WIDTH - 1);

    recursion::recursion::<MySpec<WIDTH, RATE>, WIDTH, RATE, L>(d);
}
