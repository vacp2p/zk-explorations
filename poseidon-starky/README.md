# Poseidon-Starky
This repository contains STARK circuits of a hash function called Poseidon. The implementation is based on Starky, a powerful STARK library. You can find the Poseidon hash function repository [here](https://github.com/HorizenLabs/poseidon2) and the Starky library [here](https://github.com/mir-protocol/plonky2/tree/main/starky).

## Hasher Details
The Poseidon hasher, configured with `POSEIDON_GOLDILOCKS_8_PARAMS`, operates on 8 Goldilocks elements. It takes these elements as input and produces an output. Each row in the benchmark results represents a single run of the Poseidon hasher.

## Future Improvements
1. Speed Enhancements: Future versions could potentially speed up the process. For example, we can reduce the constraints degree with more STARK table columns.

2. Support for more STATE_SIZE: The current version supports a fixed STATE_SIZE of 8. It should be relatively straightforward to adjust the code if your use case requires a larger STATE_SIZE.

## Contributing
Feel free to fork this repository and submit your pull requests for review. Any contribution that helps improve the performance of Poseidon-Starky is welcome.
