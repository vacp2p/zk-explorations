use bellpepper_core::SynthesisError;

use arecibo::errors::NovaError;

#[derive(Debug)]
pub enum Error {
    Arecibo(NovaError),
    Synthesis(SynthesisError),
}
