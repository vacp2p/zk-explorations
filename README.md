# ZK-explorations

This is a working repository for the zkVM team.

Here we are trying out various proof systems for functionality and performance.

## Benchmarks

We initiate our exploration into different Zero-knowledge proof systems by showcasing a consistent benchmark analysis using Poseidon across diverse circuits. Even though there are various other primitives for benchmarking, we’ve zeroed in on Poseidon due to its design since it allows for fewer constraints in the circuit, leading to faster proving times and potentially smaller proof sizes. Our goal is to conduct a thorough review of Poseidon’s performance across an array of zk-SNARK and zk-STARK circuit platforms, namely Nova, Halo2, Starky, and Plonky. By drawing these comparisons, our intention is to have a comprehensive view of the strengths and limitations of each tool. With this knowledge, we aspire to pinpoint the ideal framework for our specific needs.d

## Contents

Currently there are the following subprojects here:
- [halo2](https://github.com/zcash/halo2) basic [circuit](./halo2/README.md) (power of 3)
- [risc0](https://github.com/risc0/risc0) basic [circuit](./risc0/README.md)
- novanacci - [Fibonacci](https://en.wikipedia.org/wiki/Fibonacci_sequence) [circuit](./novanacci/README.md) written in vanilla (Bellman) [Nova](https://github.com/microsoft/Nova)
- plonky2-bench - [Poseidon hashing](https://www.poseidon-hash.info/) [circuit](./plonky2-bench/README.md) written in [Plonky2](https://github.com/mir-protocol/plonky2)

## Future plans

Similarly to plonky2-bench, there will be added Poseidon benchmarks for Nova, Halo2 and [starky](https://github.com/mir-protocol/plonky2/tree/main/starky) proof systems.

## Prerequisites

All subproject are build using [Rust](https://github.com/rust-lang/rust) therefore you need to have it installed.

For UNIX/Linux based systems it is done using:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Along with Rust you get Cargo installed ass well, so you don't need to deel with it separately.

