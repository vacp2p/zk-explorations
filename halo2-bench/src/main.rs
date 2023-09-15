pub mod mycircuit;
pub mod recursion;

use mycircuit::MySpec;

fn main() {
    recursion::recursion::<MySpec<3, 2>, 3, 2, 2>(3);
}
