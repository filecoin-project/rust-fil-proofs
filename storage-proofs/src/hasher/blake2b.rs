use blake2::Blake2b;

use super::{DigestHasher, Digester};

impl Digester for Blake2b {}

pub type Blake2bHasher = DigestHasher<Blake2b>;
