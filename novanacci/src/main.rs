use prove_verify::prove_and_verify;

mod circuit;
mod prove_verify;

fn main() {
    prove_and_verify(5, 64);
}
