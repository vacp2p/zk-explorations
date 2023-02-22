use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PasswordRequest {
    pub password: String,
    pub salt: [u8; 32],
}
