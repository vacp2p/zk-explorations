use bellperson::SynthesisError;

use nova::errors::NovaError;

#[derive(Debug)]
pub enum Error {
    Nova(NovaError),
    Synthesis(SynthesisError),
}
