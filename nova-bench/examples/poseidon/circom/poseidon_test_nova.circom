/*
    Copyright 2018 0KIMS association.

    This file is part of circom (Zero Knowledge Circuit Compiler).

    circom is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    circom is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with circom. If not, see <https://www.gnu.org/licenses/>.
*/

pragma circom 2.0.3;

include "poseidon_bytes.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template RecursivePoseidonTest(N, depth) {

    signal input in[4];
    signal input hash[4]; // XXX Not using this check
    signal output out[4];

    signal value[depth+1][4];

    component hasher[depth];

    value[0] <== in;

    for (var i = 0; i < depth; i++) {
        hasher[i] = PoseidonEx(4, 4);
        hasher[i].inputs <== value[i];
        hasher[i].initialState <== 0;

        value[i+1] <== hasher[i].out;
    }

    out <== value[depth];
}

template Main(depth_per_fold) {
    signal input step_in[4];
    signal output step_out[4];

    // Single fold case
    //component hasher = PoseidonBytes(32);
    //hasher.in <== step_in;

    // XXX Ignore private input check for now
    //in === step_in;
    
    //step_out <== hasher.out;

    // Many folds case
    component chainedSha = RecursivePoseidonTest(4, depth_per_fold);
    chainedSha.in <== step_in; // was in, we ignore in now
    chainedSha.hash <== step_in;

    // The final output should be same as the inputed hash
    // XXX Ignore private input check for now
    //hash === chainedSha.out;

    step_out <== chainedSha.out;
}

// render this file before compilation
component main { public [step_in] } = Main(10);