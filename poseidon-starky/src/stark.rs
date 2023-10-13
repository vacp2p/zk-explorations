use crate::columns::{
    COL_1ST_FULLROUND_STATE_START, COL_2ND_FULLROUND_STATE_START,
    COL_PARTIAL_ROUND_END_STATE_START, COL_PARTIAL_ROUND_STATE_START, NUM_COLS, ROUNDS_F, ROUNDS_P,
    SBOX_DEGREE, STATE_SIZE,
};
use ark_ff::{BigInteger, PrimeField, Fp, MontBackend};
use num::BigUint;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use zkhash_poseidon::poseidon::poseidon_params::PoseidonParams;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::stark::Stark;
use starky::vars::{StarkEvaluationTargets, StarkEvaluationVars};
use std::marker::PhantomData;
use zkhash_poseidon::fields::goldilocks::{FpGoldiLocks, FqConfig};
use zkhash_poseidon::poseidon::poseidon_instance_goldilocks::{MDS8, RC8};

fn scalar_to_fe<F: RichField + Extendable<D>, const D: usize, FE, const D2: usize, PF: PrimeField>(
    scalar: PF,
) -> FE
where
    FE: FieldExtension<D2, BaseField = F>,
{
    FE::from_canonical_u64(
        F::from_noncanonical_biguint(BigUint::from_bytes_le(&scalar.into_bigint().to_bytes_le()))
            .to_canonical_u64(),
    )
}

fn scalar_to_extension_target<F: RichField + Extendable<D>, const D: usize, PF: PrimeField>(
    scalar: PF,
) -> F::Extension
{
    F::Extension::from_canonical_u64(
        F::from_noncanonical_biguint(BigUint::from_bytes_le(&scalar.into_bigint().to_bytes_le()))
            .to_canonical_u64(),
    )
}

fn scalar_constant_extension<F: RichField + Extendable<D>, const D: usize, PF: PrimeField>(
    builder: &mut CircuitBuilder<F, D>,
    scalar: PF,
) -> ExtensionTarget<D>
{
    let extention = builder.constant_extension(scalar_to_extension_target::<F, D, PF>(scalar));

    extention
}

fn cheap_matmul_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    state: &[P; 8],
    v: &Vec<Vec<Fp<MontBackend<FqConfig, 1>, 1>>>,
    w_hat: &Vec<Vec<Fp<MontBackend<FqConfig, 1>, 1>>>,
    r: usize,
) -> [P; 8]
where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    assert_eq!(STATE_SIZE, 8);
    let mut out = [P::ZEROS; 8];
    if MDS8[0][0].0.is_zero() {
        // panic!();
    }
    out[0] = state[0] * scalar_to_fe::<F, D, FE, D2, FpGoldiLocks>(MDS8[0][0]);

    for i in 1..8 {

        if w_hat[r][i - 1].0.is_zero() {
            // panic!();
        }

        out[0] = out[0] + state[i] * scalar_to_fe::<F, D, FE, D2, FpGoldiLocks>(w_hat[r][i - 1]);
    }
    for i in 1..8 {
        out[i] = state[0];
        out[i] *= scalar_to_fe::<F, D, FE, D2, FpGoldiLocks>(v[r][i - 1]);
        out[i] += state[i];
    }

    out
}

fn cheap_matmul_constraints_recursive<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    state: &[ExtensionTarget<D>; 8],
    v: &Vec<Vec<Fp<MontBackend<FqConfig, 1>, 1>>>,
    w_hat: &Vec<Vec<Fp<MontBackend<FqConfig, 1>, 1>>>,
    r: usize,
) -> [ExtensionTarget<D>; 8]
{
    assert_eq!(STATE_SIZE, 8);

    let zero = builder.zero_extension();
    let mut out = [zero; 8];

    let mds_extension = builder.constant_extension(scalar_to_extension_target::<F, D, FpGoldiLocks>(MDS8[0][0]));
    out[0] = builder.mul_extension(state[0], mds_extension);

    for i in 1..8 {
        let w_hat_extension = builder.constant_extension(scalar_to_extension_target::<F, D, FpGoldiLocks>(w_hat[r][i - 1]));
        out[0] = builder.mul_add_extension(state[i], w_hat_extension, out[0]);
    }
    for i in 1..8 {
        let v_extension = builder.constant_extension(scalar_to_extension_target::<F, D, FpGoldiLocks>(v[r][i - 1]));
        out[i] = builder.mul_add_extension(state[0], v_extension, state[i]);
    }

    out
}

// degree: 1
fn matmul_constraints<
    F: RichField + Extendable<D>,
    const D: usize,
    FE,
    P,
    const D2: usize,
>(
    state: &[P; 8],
    opt_mat: Option<Vec<Vec<Fp<MontBackend<FqConfig, 1>, 1>>>>,
) -> [P; 8]
where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    assert_eq!(STATE_SIZE, 8);
    let mut out = [P::ZEROS; 8];

    let mat = opt_mat.unwrap_or_else(|| MDS8.to_vec());

    for i in 0..STATE_SIZE {
        for (col, inp) in state.iter().enumerate().take(STATE_SIZE) {
            if mat[i][col].0.is_zero() {
                // panic!();
            }

            out[i] = out[i] + *inp * scalar_to_fe::<F, D, FE, D2, FpGoldiLocks>(mat[i][col]);
        }
    }
    out
}


fn matmul_constraints_recursive<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    state: &[ExtensionTarget<D>; 8],
    opt_mat: Option<Vec<Vec<Fp<MontBackend<FqConfig, 1>, 1>>>>,
) -> [ExtensionTarget<D>; 8]
{
    assert_eq!(STATE_SIZE, 8);

    let mat = opt_mat.unwrap_or_else(|| MDS8.to_vec());

    let zero = builder.zero_extension();
    let mut out = [zero; 8];

    for i in 0..STATE_SIZE {
        for (col, inp) in state.iter().enumerate().take(STATE_SIZE) {
            let tmp_extension = builder.constant_extension(scalar_to_extension_target::<F, D, FpGoldiLocks>(mat[i][col]));

            out[i] = builder.mul_add_extension(*inp, tmp_extension, out[i]);
        }
    }

    out
}


// degree: 1
fn add_rc_constraints<F: RichField + Extendable<D>, const D: usize, FE, P, const D2: usize>(
    state: &[P; 8],
    r: usize,
    opt: bool,
) -> [P; 8]
where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    assert_eq!(STATE_SIZE, 8);
    let mut out = [P::ZEROS; 8];

    let rc: Vec<Vec<FpGoldiLocks>> = if opt {
        PoseidonParams::equivalent_round_constants(&RC8, &MDS8, ROUNDS_F / 2, ROUNDS_P)
    } else {
        RC8.to_vec()
    };

    for i in 0..8 {
        if rc[r][i].0.is_zero() {
            // panic!();
        }
        out[i] = state[i] + scalar_to_fe::<F, D, FE, D2, FpGoldiLocks>(rc[r][i]);
    }

    out
}

fn add_rc_constraints_recursive<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: &[ExtensionTarget<D>; 8],
    r: usize,
    opt: bool,
) -> [ExtensionTarget<D>; 8]
{
    assert_eq!(STATE_SIZE, 8);

    let zero = builder.zero_extension();
    let mut out = [zero; 8];

    let rc: Vec<Vec<FpGoldiLocks>> = if opt {
        PoseidonParams::equivalent_round_constants(&RC8, &MDS8, ROUNDS_F / 2, ROUNDS_P)
    } else {
        RC8.to_vec()
    };
    
    for i in 0..8 {
        let rc8_extension = builder.constant_extension(scalar_to_extension_target::<F, D, FpGoldiLocks>(rc[r][i]));
        out[i] = builder.add_extension(state[i], rc8_extension);
    }

    out
}

// degree: SBOX_DEGREE (7)
fn sbox_p_constraints<F: RichField + Extendable<D>, const D: usize, FE, P, const D2: usize>(
    state: &P,
) -> P
where
    FE: FieldExtension<D2, BaseField = F>,
    P: PackedField<Scalar = FE>,
{
    assert_eq!(STATE_SIZE, 8);
    let mut out = P::ONES;

    for _ in 0..SBOX_DEGREE {
        out = out.mul(*state);
    }

    out
}

fn sbox_p_constraints_recursive<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: &ExtensionTarget<D>,
) -> ExtensionTarget<D>
{
    assert_eq!(STATE_SIZE, 8);
    let one = builder.one_extension();
    let mut out = one;

    for _ in 0..SBOX_DEGREE {
        out = builder.mul_extension(out, *state);
    }

    out
}

#[derive(Copy, Clone, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct PoseidonStark<F, const D: usize> {
    pub _f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for PoseidonStark<F, D> {
    const COLUMNS: usize = NUM_COLS;
    const PUBLIC_INPUTS: usize = 0;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let lv = vars.local_values;
        let mut state = lv[0..STATE_SIZE].try_into().unwrap();

        let (m_i, v, w_hat) = PoseidonParams::equivalent_matrices(&MDS8, STATE_SIZE, ROUNDS_P);

        // first full rounds
        for r in 0..ROUNDS_F {
            state = add_rc_constraints(&state, r, false);
            #[allow(clippy::needless_range_loop)]
            for i in 0..STATE_SIZE {
                state[i] = sbox_p_constraints(&state[i]);
            }
            state = matmul_constraints(&state, None);
            for i in 0..STATE_SIZE {
                yield_constr
                    .constraint(state[i] - lv[COL_1ST_FULLROUND_STATE_START + r * STATE_SIZE + i]);
                state[i] = lv[COL_1ST_FULLROUND_STATE_START + r * STATE_SIZE + i];
            }
        }

        let p_end = ROUNDS_F + ROUNDS_P;

        // partial rounds
        for i in 0..ROUNDS_P {
            let r = ROUNDS_F + i;
            state = add_rc_constraints(&state, r, false);
            state[0] = sbox_p_constraints(&state[0]);            
            state = matmul_constraints(&state, None);
            yield_constr.constraint(state[0] - lv[COL_PARTIAL_ROUND_STATE_START + i]);
            state[0] = lv[COL_PARTIAL_ROUND_STATE_START + i];
        }

        // the state before last full rounds
        for i in 0..STATE_SIZE {
            yield_constr.constraint(state[i] - lv[COL_PARTIAL_ROUND_END_STATE_START + i]);
            state[i] = lv[COL_PARTIAL_ROUND_END_STATE_START + i];
        }

        // last full rounds
        for i in 0..ROUNDS_F {
            let r = ROUNDS_F + ROUNDS_P + i;
            state = add_rc_constraints(&state, r, false);
            #[allow(clippy::needless_range_loop)]
            for j in 0..STATE_SIZE {
                state[j] = sbox_p_constraints(&state[j]);
            }
            state = matmul_constraints(&state, None);
            for j in 0..STATE_SIZE {
                yield_constr
                    .constraint(state[j] - lv[COL_2ND_FULLROUND_STATE_START + i * STATE_SIZE + j]);
                state[j] = lv[COL_2ND_FULLROUND_STATE_START + i * STATE_SIZE + j];
            }
        }
    }

    fn constraint_degree(&self) -> usize {
        7
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let lv = vars.local_values;
        let mut state = lv[0..STATE_SIZE].try_into().unwrap();

        let (m_i, v, w_hat) = PoseidonParams::equivalent_matrices(&MDS8, STATE_SIZE, ROUNDS_P);

        // first full rounds
        for r in 0..ROUNDS_F {
            state = add_rc_constraints_recursive(builder, &state, r, false);
            #[allow(clippy::needless_range_loop)]
            for i in 0..STATE_SIZE {
                state[i] = sbox_p_constraints_recursive(builder, &state[i]);
            }
            state = matmul_constraints_recursive(builder, &state, None);
            for i in 0..STATE_SIZE {
                let constraint = builder.sub_extension(state[i], lv[COL_1ST_FULLROUND_STATE_START + r * STATE_SIZE + i]);
                yield_constr.constraint(builder, constraint);
                state[i] = lv[COL_1ST_FULLROUND_STATE_START + r * STATE_SIZE + i];
            }
        }

        let opt_round_constants = PoseidonParams::equivalent_round_constants(&RC8, &MDS8, ROUNDS_F / 2, ROUNDS_P);

        let p_end = ROUNDS_F + ROUNDS_P;

        // partial rounds
        for i in 0..ROUNDS_P {
            let r = ROUNDS_F + i;
            state = add_rc_constraints_recursive(builder, &state, r, false);
            state[0] = sbox_p_constraints_recursive(builder, &state[0]);
            state = matmul_constraints_recursive(builder, &state, None);
            let constraint = builder.sub_extension(state[0], lv[COL_PARTIAL_ROUND_STATE_START + i]);
            yield_constr.constraint(builder, constraint);
            state[0] = lv[COL_PARTIAL_ROUND_STATE_START + i];
        }

        // the state before last full rounds
        for i in 0..STATE_SIZE {
            let constraint = builder.sub_extension(state[i], lv[COL_PARTIAL_ROUND_END_STATE_START + i]);
            yield_constr.constraint(builder, constraint);
            state[i] = lv[COL_PARTIAL_ROUND_END_STATE_START + i];
        }

        // last full rounds
        for i in 0..ROUNDS_F {
            let r = ROUNDS_F + ROUNDS_P + i;
            state = add_rc_constraints_recursive(builder, &state, r, false);
            #[allow(clippy::needless_range_loop)]
            for j in 0..STATE_SIZE {
                state[j] = sbox_p_constraints_recursive(builder, &state[j]);
            }
            state = matmul_constraints_recursive(builder, &state, None);
            for j in 0..STATE_SIZE {
                let constraint = builder.sub_extension(state[j], lv[COL_2ND_FULLROUND_STATE_START + i * STATE_SIZE + j]);
                yield_constr.constraint(builder, constraint);
                state[j] = lv[COL_2ND_FULLROUND_STATE_START + i * STATE_SIZE + j];
            }
        }
    }
}

pub fn trace_to_poly_values<F: Field, const COLUMNS: usize>(
    trace: [Vec<F>; COLUMNS],
) -> Vec<PolynomialValues<F>> {
    trace.into_iter().map(PolynomialValues::new).collect()
}
