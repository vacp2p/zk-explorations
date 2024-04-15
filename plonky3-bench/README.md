# plonky3-bench

[Poseidon Hash function](https://www.poseidon-hash.info/) [circuit](p3-poseidon) written in [Plonky3](https://github.com/Plonky3/Plonky3)

## Usage

```bash
cargo build
```

Running

```bash
RUST_LOG=info cargo run --example prove_goldilocks_poseidon --release --features parallel
```
