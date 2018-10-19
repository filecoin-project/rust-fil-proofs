use blake2::Blake2s;

use super::{DigestHasher, Digester};

impl Digester for Blake2s {}

pub type Blake2sHasher = DigestHasher<Blake2s>;
