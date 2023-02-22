#![no_main]

use core::PasswordRequest;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Sha, sha};

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let request: PasswordRequest = env::read();

    let policy = PasswordPolicy {
        min_length: 3,
        max_length: 64,
        min_numeric: 2,
        min_uppercase: 2,
        min_lowercase: 2,
        min_special_chars: 1,
    };

    if !policy.is_valid(&request.password) {
        panic!("Password invalid. Please try again.");
    }

    let mut salted_password = request.password.as_bytes().to_vec();
    salted_password.extend(request.salt);
    let password_hash = sha().hash_bytes(&salted_password[..]);

    env::commit(&*password_hash);
    env::commit(&request.salt);
}

struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: usize,
    pub min_uppercase: usize,
    pub min_lowercase: usize,
    pub min_numeric: usize,
    pub min_special_chars: usize,
}

impl PasswordPolicy {
    pub fn is_valid(&self, pw: &str) -> bool {
        let metrics = PasswordMetrics::new(pw);
        self.correct_length(pw)
            && (metrics.numeric >= self.min_numeric)
            && (metrics.uppercase >= self.min_uppercase)
            && (metrics.lowercase >= self.min_lowercase)
            && (metrics.special >= self.min_special_chars)
    }

    fn correct_length(&self, password: &str) -> bool {
        password.len() > (self.min_length - 1) && password.len() < (self.max_length + 1)
    }
}

struct PasswordMetrics {
    pub numeric: usize,
    pub special: usize,
    pub uppercase: usize,
    pub lowercase: usize,
}

impl PasswordMetrics {
    pub fn new(password: &str) -> Self {
        let mut numeric = 0;
        let mut special = 0;
        let mut uppercase = 0;
        let mut lowercase = 0;
        for ch in password.chars() {
            if ch.is_ascii_digit() {
                numeric += 1;
            }
            if ch.is_ascii_punctuation() {
                special += 1;
            }
            if ch.is_ascii_uppercase() {
                uppercase += 1;
            }
            if ch.is_ascii_lowercase() {
                lowercase += 1;
            }
        }
        PasswordMetrics {
            numeric,
            special,
            uppercase,
            lowercase,
        }
    }
}
