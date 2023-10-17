# Nova

Using https://github.com/nalinbhardwaj/Nova-Scotia

## To run

One time:

- Ensure Circom is setup correctly with Pasta curves (see Nova Scotia README)
- Ensure submodules updates
- Run `npm install` from internal circom folder
- Run `./examples/poseidon/circom/compile_vesta.sh`

Then:

`cargo run --example poseidon`