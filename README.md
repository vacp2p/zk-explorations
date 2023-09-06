# ZK-explorations

This is a working repository for the zkVM team.

Here we are trying out various proof systems for functionality and performance.

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

