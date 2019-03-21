use blake2::Blake2b;

use super::{DigestHasher, Digester};

impl Digester for Blake2b {
    fn name() -> String {
        "Blake2b".into()
    }
}

pub type Blake2bHasher = DigestHasher<Blake2b>;
