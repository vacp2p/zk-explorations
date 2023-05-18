use core::fmt::Debug;
use ff::Field;

use pasta_curves::{pallas, vesta};
use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::ops::{Add, Sub, SubAssign};
use std::sync::Arc;

use nova::traits::Group;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EvalMode {
    LTRSequential,
    LTRAddChainSequential,
    RTLSequential,
    RTLAddChainSequential,
}

impl EvalMode {
    pub fn all() -> Vec<EvalMode> {
        vec![
            Self::LTRSequential,
            Self::LTRAddChainSequential,
            Self::RTLSequential,
            Self::RTLAddChainSequential,
        ]
    }
}

#[derive(Debug)]
struct Sq(Arc<UnsafeCell<Box<[[u64; 4]]>>>);
unsafe impl Send for Sq {}
unsafe impl Sync for Sq {}

/// Modulus is that of `Fq`, which is the base field of `Vesta` and scalar field of `Pallas`.
#[derive(Debug, PartialEq)]
pub struct PallasVDF {
    eval_mode: EvalMode,
}

impl MinRootVDF<pallas::Point> for PallasVDF {
    fn new_with_mode(eval_mode: EvalMode) -> Self {
        PallasVDF { eval_mode }
    }

    // To bench with this on 3970x:
    // RUSTFLAG="-C target-cpu=native -g" taskset -c 0,40 cargo bench
    fn eval(&mut self, x: State<pallas::Scalar>, t: u64) -> State<pallas::Scalar> {
        match self.eval_mode {
            EvalMode::LTRSequential
            | EvalMode::LTRAddChainSequential
            | EvalMode::RTLAddChainSequential
            | EvalMode::RTLSequential => self.simple_eval(x, t),
        }
    }

    fn element(n: u64) -> pallas::Scalar {
        pallas::Scalar::from(n)
    }

    fn exponent() -> [u64; 4] {
        FQ_RESCUE_INVALPHA
    }

    fn inverse_exponent() -> u64 {
        5
    }

    /// Pallas' inverse_exponent is 5, so we can hardcode this.
    fn inverse_step(x: pallas::Scalar) -> pallas::Scalar {
        x.mul(&x.square().square())
    }

    fn forward_step(&mut self, x: pallas::Scalar) -> pallas::Scalar {
        match self.eval_mode {
            EvalMode::LTRSequential => self.forward_step_ltr_sequential(x),
            EvalMode::RTLSequential => self.forward_step_rtl_sequential(x),
            EvalMode::RTLAddChainSequential => self.forward_step_sequential_rtl_addition_chain(x),
            EvalMode::LTRAddChainSequential => self.forward_step_ltr_addition_chain(x),
        }
    }
}

impl PallasVDF {
    fn forward_step_ltr_addition_chain(&mut self, x: pallas::Scalar) -> pallas::Scalar {
        let sqr = |x: pallas::Scalar, i: u32| (0..i).fold(x, |x, _| x.square());

        let mul = |x: pallas::Scalar, y| x.mul(y);
        let sqr_mul = |x, n, y: pallas::Scalar| y.mul(&sqr(x, n));

        let q1 = x;
        let q10 = sqr(q1, 1);
        let q11 = mul(q10, &q1);
        let q101 = mul(q10, &q11);
        let q110 = sqr(q11, 1);
        let q111 = mul(q110, &q1);
        let q1001 = mul(q111, &q10);
        let q1111 = mul(q1001, &q110);
        let qr2 = sqr_mul(q110, 3, q11);
        let qr4 = sqr_mul(qr2, 8, qr2);
        let qr8 = sqr_mul(qr4, 16, qr4);
        let qr16 = sqr_mul(qr8, 32, qr8);
        let qr32 = sqr_mul(qr16, 64, qr16);
        let qr32a = sqr_mul(qr32, 5, q1001);
        let qr32b = sqr_mul(qr32a, 8, q111);
        let qr32c = sqr_mul(qr32b, 4, q1);
        let qr32d = sqr_mul(qr32c, 2, qr4);
        let qr32e = sqr_mul(qr32d, 7, q11);
        let qr32f = sqr_mul(qr32e, 6, q1001);
        let qr32g = sqr_mul(qr32f, 3, q101);
        let qr32h = sqr_mul(qr32g, 7, q101);
        let qr32i = sqr_mul(qr32h, 7, q111);
        let qr32j = sqr_mul(qr32i, 4, q111);
        let qr32k = sqr_mul(qr32j, 5, q1001);
        let qr32l = sqr_mul(qr32k, 5, q101);
        let qr32m = sqr_mul(qr32l, 3, q11);
        let qr32n = sqr_mul(qr32m, 4, q101);
        let qr32o = sqr_mul(qr32n, 3, q101);
        let qr32p = sqr_mul(qr32o, 6, q1111);
        let qr32q = sqr_mul(qr32p, 4, q1001);
        let qr32r = sqr_mul(qr32q, 6, q101);
        let qr32s = sqr_mul(qr32r, 37, qr8);
        sqr_mul(qr32s, 2, q1)
    }

    // Sequential RTL square-and-multiply.
    fn forward_step_rtl_sequential(&mut self, x: pallas::Scalar) -> pallas::Scalar {
        (0..254)
            .scan(x, |state, _| {
                let ret = *state;
                *state = (*state).square();
                Some(ret)
            })
            .fold(
                (Self::exponent(), pallas::Scalar::one(), 0),
                |(mut remaining, acc, count), elt| {
                    let limb_index = count / 64;
                    let limb = remaining[limb_index];

                    let one = (limb & 1) == 1;
                    let acc = if one { acc.mul(&elt) } else { acc };
                    remaining[limb_index] = limb >> 1;

                    (remaining, acc, count + 1)
                },
            )
            .1
    }

    // Sequential RTL square-and-multiply with optimized addition chain.
    fn forward_step_sequential_rtl_addition_chain(&mut self, x: pallas::Scalar) -> pallas::Scalar {
        let first_section_bit_count = 128;
        let acc = pallas::Scalar::one();

        // First section is same as rtl without addition chain.
        let (_, acc, _, square_acc) = (0..first_section_bit_count)
            .scan(x, |state, _| {
                let ret = *state;
                *state = (*state).square();
                Some(ret)
            })
            .fold(
                (Self::exponent(), acc, 0, pallas::Scalar::zero()),
                |(mut remaining, acc, count, _previous_elt), elt| {
                    let limb_index = count / 64;
                    let limb = remaining[limb_index];

                    let one = (limb & 1) == 1;
                    let acc = if one { acc.mul(&elt) } else { acc };
                    remaining[limb_index] = limb >> 1;

                    (remaining, acc, count + 1, elt)
                },
            );

        let square_acc = square_acc.mul(&square_acc.square());
        let square_acc = square_acc.mul(&square_acc.square().square().square().square());

        (0..122)
            .scan(square_acc, |state, _| {
                *state = (*state).square();

                Some(*state)
            })
            .fold((acc, 1), |(acc, count), elt| {
                if count % 8 == 1 {
                    (acc.mul(&elt), count + 1)
                } else {
                    (acc, count + 1)
                }
            })
            .0
    }
}

/// Modulus is that of `Fp`, which is the base field of `Pallas and scalar field of Vesta.
#[derive(Debug)]
pub struct VestaVDF {}
impl MinRootVDF<vesta::Point> for VestaVDF {
    fn new_with_mode(_eval_mode: EvalMode) -> Self {
        VestaVDF {}
    }

    fn element(n: u64) -> vesta::Scalar {
        vesta::Scalar::from(n)
    }

    fn exponent() -> [u64; 4] {
        FP_RESCUE_INVALPHA
    }

    fn inverse_exponent() -> u64 {
        5
    }

    fn inverse_step(x: vesta::Scalar) -> vesta::Scalar {
        x.mul(&x.square().square())
    }

    fn forward_step(&mut self, x: vesta::Scalar) -> vesta::Scalar {
        let sqr = |x: vesta::Scalar, i: u32| (0..i).fold(x, |x, _| x.square());

        let mul = |x: vesta::Scalar, y| x.mul(y);
        let sqr_mul = |x, n, y: vesta::Scalar| y.mul(&sqr(x, n));

        let p1 = x;
        let p10 = sqr(p1, 1);
        let p11 = mul(p10, &p1);
        let p101 = mul(p10, &p11);
        let p110 = sqr(p11, 1);
        let p111 = mul(p110, &p1);
        let p1001 = mul(p111, &p10);
        let p1111 = mul(p1001, &p110);
        let pr2 = sqr_mul(p110, 3, p11);
        let pr4 = sqr_mul(pr2, 8, pr2);
        let pr8 = sqr_mul(pr4, 16, pr4);
        let pr16 = sqr_mul(pr8, 32, pr8);
        let pr32 = sqr_mul(pr16, 64, pr16);
        let pr32a = sqr_mul(pr32, 5, p1001);
        let pr32b = sqr_mul(pr32a, 8, p111);
        let pr32c = sqr_mul(pr32b, 4, p1);
        let pr32d = sqr_mul(pr32c, 2, pr4);
        let pr32e = sqr_mul(pr32d, 7, p11);
        let pr32f = sqr_mul(pr32e, 6, p1001);
        let pr32g = sqr_mul(pr32f, 3, p101);
        let pr32h = sqr_mul(pr32g, 5, p1);
        let pr32i = sqr_mul(pr32h, 7, p101);
        let pr32j = sqr_mul(pr32i, 4, p11);
        let pr32k = sqr_mul(pr32j, 8, p111);
        let pr32l = sqr_mul(pr32k, 4, p1);
        let pr32m = sqr_mul(pr32l, 4, p111);
        let pr32n = sqr_mul(pr32m, 9, p1111);
        let pr32o = sqr_mul(pr32n, 8, p1111);
        let pr32p = sqr_mul(pr32o, 6, p1111);
        let pr32q = sqr_mul(pr32p, 2, p11);
        let pr32r = sqr_mul(pr32q, 34, pr8);
        sqr_mul(pr32r, 2, p1)
    }
}

// Question: Is this right, or is it the reverse? Which scalar fields' modulus do we want to target?
pub type TargetVDF<'a> = PallasVDF;

#[derive(std::cmp::PartialEq, Debug, Clone, Copy)]
pub struct State<T> {
    pub x: T,
    pub y: T,
    pub i: T,
}
const FP_RESCUE_INVALPHA: [u64; 4] = [
    0xe0f0f3f0cccccccd,
    0x4e9ee0c9a10a60e2,
    0x3333333333333333,
    0x3333333333333333,
];

const FQ_RESCUE_INVALPHA: [u64; 4] = [
    0xd69f2280cccccccd,
    0x4e9ee0c9a143ba4a,
    0x3333333333333333,
    0x3333333333333333,
];

pub trait MinRootVDF<G>: Debug
where
    G: Group,
{
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::new_with_mode(Self::default_mode())
    }

    fn new_with_mode(eval_mode: EvalMode) -> Self;

    fn default_mode() -> EvalMode {
        EvalMode::LTRSequential
    }

    /// Exponent used to take a root in the 'slow' direction.
    fn exponent() -> [u64; 4];

    /// Exponent used in the 'fast' direction.
    fn inverse_exponent() -> u64;

    #[inline]
    /// The building block of a round in the slow, 'forward' direction.
    fn forward_step_ltr_sequential(&mut self, x: G::Scalar) -> G::Scalar {
        x.pow_vartime(Self::exponent())
    }

    #[inline]
    /// The building block of a round in the slow, 'forward' direction.
    fn forward_step(&mut self, x: G::Scalar) -> G::Scalar {
        self.forward_step_ltr_sequential(x)
    }

    #[inline]
    /// The building block of a round in the fast, 'inverse' direction.
    fn inverse_step(x: G::Scalar) -> G::Scalar {
        x.pow_vartime([Self::inverse_exponent(), 0, 0, 0])
    }

    /// one round in the slow/forward direction.
    fn round(&mut self, s: State<G::Scalar>) -> State<G::Scalar> {
        State {
            x: self.forward_step(G::Scalar::add(s.x, s.y)),
            y: G::Scalar::add(s.x, s.i),
            i: G::Scalar::add(s.i, G::Scalar::one()),
        }
    }

    /// One round in the fast/inverse direction.
    fn inverse_round(s: State<G::Scalar>) -> State<G::Scalar> {
        let i = G::Scalar::sub(s.i, &G::Scalar::one());
        let x = G::Scalar::sub(s.y, &i);
        let mut y = Self::inverse_step(s.x);
        y.sub_assign(&x);
        State { x, y, i }
    }

    /// Evaluate input `x` with time/difficulty parameter, `t` in the
    /// slow/forward direction.
    fn eval(&mut self, x: State<G::Scalar>, t: u64) -> State<G::Scalar> {
        self.simple_eval(x, t)
    }

    fn simple_eval(&mut self, x: State<G::Scalar>, t: u64) -> State<G::Scalar> {
        let mut acc = x;
        for _ in 0..t {
            acc = self.round(acc);
        }

        acc
    }

    /// Invert evaluation of output `x` with time/difficulty parameter, `t` in
    /// the fast/inverse direction.
    fn inverse_eval(x: State<G::Scalar>, t: u64) -> State<G::Scalar> {
        (0..t).fold(x, |acc, _| Self::inverse_round(acc))
    }

    /// Quickly check that `result` is the result of having slowly evaluated
    /// `original` with time/difficulty parameter `t`.
    fn check(result: State<G::Scalar>, t: u64, original: State<G::Scalar>) -> bool {
        original == Self::inverse_eval(result, t)
    }

    fn element(n: u64) -> G::Scalar;
}

#[derive(Debug, PartialEq)]
pub struct Evaluation<V: MinRootVDF<G> + Debug, G: Group> {
    pub result: State<G::Scalar>,
    pub t: u64,
    _v: PhantomData<V>,
}

impl<V: MinRootVDF<G>, G: Group> Clone for Evaluation<V, G> {
    fn clone(&self) -> Self {
        Self {
            result: self.result,
            t: self.t,
            _v: PhantomData::<V>::default(),
        }
    }
}

impl<V: MinRootVDF<G>, G: Group> Evaluation<V, G> {
    pub fn eval(x: State<G::Scalar>, t: u64) -> (Vec<G::Scalar>, Self) {
        let mut vdf = V::new();
        let result = vdf.eval(x, t);

        let z0 = vec![result.x, result.y, result.i];

        (
            z0,
            Self {
                result,
                t,
                _v: PhantomData::<V>,
            },
        )
    }

    pub fn eval_with_mode(eval_mode: EvalMode, x: State<G::Scalar>, t: u64) -> Self {
        let mut vdf = V::new_with_mode(eval_mode);
        let result = vdf.eval(x, t);
        Self {
            result,
            t,
            _v: PhantomData::<V>,
        }
    }

    pub fn result(&self) -> State<G::Scalar> {
        self.result
    }

    pub fn verify(&self, original: State<G::Scalar>) -> bool {
        V::check(self.result, self.t, original)
    }

    pub fn append(&self, other: Self) -> Option<Self> {
        if other.verify(self.result) {
            Some(Self {
                result: other.result,
                t: self.t + other.t,
                _v: PhantomData::<V>,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_SEED;

    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_exponents() {
        test_exponents_aux::<PallasVDF, pallas::Point>();
        test_exponents_aux::<VestaVDF, vesta::Point>();
    }

    fn test_exponents_aux<V: MinRootVDF<G>, G: Group>() {
        assert_eq!(V::inverse_exponent(), 5);
        assert_eq!(V::inverse_exponent(), 5);
    }

    #[test]
    fn test_steps() {
        test_steps_aux::<PallasVDF, pallas::Point>();
        test_steps_aux::<VestaVDF, vesta::Point>();
    }

    fn test_steps_aux<V: MinRootVDF<G>, G: Group>() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let mut vdf = V::new();

        for _ in 0..100 {
            let x = G::Scalar::random(&mut rng);
            let y = vdf.forward_step(x);
            let z = V::inverse_step(y);

            assert_eq!(x, z);
        }
    }

    #[test]
    fn test_eval() {
        println!("top");
        test_eval_aux::<PallasVDF, pallas::Point>();
    }

    fn test_eval_aux<V: MinRootVDF<G>, G: Group>() {
        for mode in EvalMode::all().iter() {
            test_eval_aux2::<V, G>(*mode)
        }
    }

    fn test_eval_aux2<V: MinRootVDF<G>, G: Group>(eval_mode: EvalMode) {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let mut vdf = V::new_with_mode(eval_mode);

        for _ in 0..10 {
            let t = 10;
            let x = G::Scalar::random(&mut rng);
            let y = G::Scalar::random(&mut rng);
            let x = State {
                x,
                y,
                i: G::Scalar::zero(),
            };
            let result = vdf.eval(x, t);
            let again = V::inverse_eval(result, t);

            assert_eq!(x, again);
            assert!(V::check(result, t, x));
        }
    }

    #[test]
    fn test_vanilla_proof() {
        test_vanilla_proof_aux::<PallasVDF, pallas::Point>();
        test_vanilla_proof_aux::<VestaVDF, vesta::Point>();
    }

    fn test_vanilla_proof_aux<V: MinRootVDF<G>, G: Group>() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        let x = G::Scalar::random(&mut rng);
        let y = G::Scalar::zero();
        let x = State {
            x,
            y,
            i: G::Scalar::zero(),
        };
        let t = 4;
        let n = 3;

        let (_z0, first_proof) = Evaluation::<V, G>::eval(x, t);

        let final_proof = (1..n).fold(first_proof, |acc, _| {
            let (_, new_proof) = Evaluation::<V, G>::eval(acc.result, t);

            acc.append(new_proof).expect("failed to append proof")
        });

        assert_eq!(V::element(final_proof.t), final_proof.result.i);
        assert_eq!(n * t, final_proof.t);
        assert!(final_proof.verify(x));
    }
}
