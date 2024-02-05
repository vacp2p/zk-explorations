use bellpepper_core::SynthesisError;

use arecibo::errors::NovaError;

#[derive(Debug)]
pub enum Error {
    Nova(NovaError),
    Synthesis(SynthesisError),
}
