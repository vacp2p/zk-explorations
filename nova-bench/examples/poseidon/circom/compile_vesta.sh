#!/bin/bash

circom ./examples/poseidon/circom/poseidon_test_nova.circom --r1cs --wasm --sym --c --output ./examples/poseidon/circom/ --prime vesta
#circom ./examples/poseidon/circom/poseidon_test_nova.circom --r1cs --wasm --sym --c --output ./examples/poseidon/circom/ --prime pallas

#Doesn't work on M1, using WASM instead
#cd examples/poseidon/circom/toy_cpp && make

# NOTE: This is just one step of the computation
# Full computation happens inside poseidon_wasm.rs
(cd ./examples/poseidon/circom/poseidon_test_nova_js && node generate_witness.js poseidon_test_nova.wasm ../input_32_first_step.json output.wtns)

# Doesn't work on M1
#(cd ./examples/poseidon/circom/poseidon_test_nova_cpp && make)
