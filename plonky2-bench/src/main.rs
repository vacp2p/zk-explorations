use anyhow::Result;

pub mod common;
pub mod recursion;

fn main() -> Result<()> {
    recursion::recursion(2)
}
