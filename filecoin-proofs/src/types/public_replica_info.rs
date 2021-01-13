use std::cmp::Ordering;
use std::hash::Hash;

use anyhow::{ensure, Result};
use filecoin_hashers::Domain;

use crate::{api::as_safe_commitment, types::Commitment};

/// The minimal information required about a replica, in order to be able to verify
/// a PoSt over it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicReplicaInfo {
    /// The replica commitment.
    comm_r: Commitment,
}

impl Ord for PublicReplicaInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.comm_r.as_ref().cmp(other.comm_r.as_ref())
    }
}

impl PartialOrd for PublicReplicaInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PublicReplicaInfo {
    pub fn new(comm_r: Commitment) -> Result<Self> {
        ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
        Ok(PublicReplicaInfo { comm_r })
    }

    pub fn safe_comm_r<T: Domain>(&self) -> Result<T> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }
}
