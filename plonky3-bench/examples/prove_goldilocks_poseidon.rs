use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
use p3_goldilocks::Goldilocks;
use p3_field::Field;
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_merkle_tree::FieldMerkleTreeMmcs;
//use p3_poseidon2::{DiffusionMatrixGoldilocks, Poseidon2};
use p3_mds::goldilocks::MdsMatrixGoldilocks;
use p3_poseidon::Poseidon;
use p3_symmetric::TruncatedPermutation;
use p3_symmetric::PaddingFreeSponge;
use p3_uni_stark::{prove, verify, StarkConfig, VerificationError};
use rand::{random, thread_rng};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

const NUM_HASHES: usize = 680;

fn main() -> Result<(), VerificationError> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 2>; 

    // Perm tipini oluşturalım.
    // Poseidon vs Poseidon2'ye göre nasıl bir farklılık var.
    type Perm = Poseidon<Val, MdsMatrixGoldilocks, 8, 7>; // normalde 16
    let perm = Perm::new_from_rng(4, 22, MdsMatrixGoldilocks, &mut thread_rng());

    type H4 = PaddingFreeSponge<Perm, 8, 4, 4>; // Bunu 8, 4, 4 olarak değiştirelim. out emin değiliz.
    let h4 = H4::new(perm.clone());

    type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>; // N -> permutation rounds 8 gibi // 4 ile değiştirebiliriz.
    let compress = MyCompress::new(perm.clone());

    // ?? valmmcs digest element size ne olmalıdır?
    // 8 yapmışlar poseidon2 için
    // Buradan öncesi poseidon permutation, buradan sonrası ise vector commitment
    type ValMmcs = FieldMerkleTreeMmcs<<Val as Field>::Packing, H4, MyCompress, 4>;
    let val_mmcs = ValMmcs::new(h4, compress);


    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Dft = Radix2DitParallel;
    let dft = Dft {};

    type Challenger = DuplexChallenger<Val, Perm, 8>;

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    type Pcs =
        TwoAdicFriPcs<TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>>;
    let pcs = Pcs::new(fri_config, dft, val_mmcs);

    type MyConfig = StarkConfig<Val, Challenge, Pcs, Challenger>;
    let config = StarkConfig::new(pcs);

    let mut challenger = Challenger::new(perm.clone());

    let inputs = (0..NUM_HASHES).map(|_| random()).collect::<Vec<_>>();
    let trace = generate_trace_rows::<Val>(inputs);
    let proof = prove::<MyConfig, _>(&config, &KeccakAir {}, &mut challenger, trace);

    let mut challenger = Challenger::new(perm);
    verify(&config, &KeccakAir {}, &mut challenger, &proof)
}
