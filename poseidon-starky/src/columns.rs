/// The size of the state
pub const STATE_SIZE: usize = 8;
pub(crate) const SBOX_DEGREE: usize = 7;

/// Poseidon constants
pub(crate) const ROUNDS_F: usize = 4;
pub(crate) const ROUNDS_P: usize = 22;

/// The starting point of the column input
pub(crate) const COL_INPUT_START: usize = 0;

/// The starting point of the state after each 1st full round
pub(crate) const COL_1ST_FULLROUND_STATE_START: usize = COL_INPUT_START + STATE_SIZE; // 8

/// The value of state[0] after each partial round
pub(crate) const COL_PARTIAL_ROUND_STATE_START: usize =
    COL_1ST_FULLROUND_STATE_START + STATE_SIZE * ROUNDS_F; // 40

/// The starting point of the state after the partial round
pub(crate) const COL_PARTIAL_ROUND_END_STATE_START: usize =
    COL_PARTIAL_ROUND_STATE_START + ROUNDS_P - 1; // 61

/// The starting point of the state after each 2nd full round
pub(crate) const COL_2ND_FULLROUND_STATE_START: usize =
    COL_PARTIAL_ROUND_END_STATE_START + STATE_SIZE; // 69

/// The starting point of the column output
/// This is the same as the last state after the 2nd full round
pub(crate) const COL_OUTPUT_START: usize =
    COL_2ND_FULLROUND_STATE_START + STATE_SIZE * (ROUNDS_F - 1);

/// The total number of columns
pub(crate) const NUM_COLS: usize = COL_2ND_FULLROUND_STATE_START + STATE_SIZE * ROUNDS_F; // 101
