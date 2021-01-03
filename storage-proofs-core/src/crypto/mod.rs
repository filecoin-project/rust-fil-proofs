use sha2::{Digest, Sha256};
pub mod aes;
pub mod feistel;
pub mod sloth;
pub mod xor;

pub struct DomainSeparationTag(&'static str);

pub const DRSAMPLE_DST: DomainSeparationTag = DomainSeparationTag("Filecoin_DRSample");
pub const FEISTEL_DST: DomainSeparationTag = DomainSeparationTag("Filecoin_Feistel");

pub fn derive_porep_domain_seed(
    domain_separation_tag: DomainSeparationTag,
    porep_id: [u8; 32],
) -> [u8; 32] {
    Sha256::new()
        .chain(domain_separation_tag.0)
        .chain(porep_id)
        .finalize()
        .into()
}
