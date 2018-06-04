
use porep::{self, PoRep};
use drgraph::{Graph, Sampling};
use vde;

use error::Result;
use proof::ProofScheme;

pub struct PublicInputs<'a> {
    prover_id: &'a [u8],
    challenge: usize,
    tau: &'a porep::Tau,
}

pub struct PrivateInputs<'a> {
    replica: &'a [u8],
    aux: &'a porep::ProverAux,
}

pub struct SetupParams {
    lambda: usize,
    drg: DrgParams,
}

pub struct DrgParams {
    n: usize,
    m: usize,
}

pub struct PublicParams {
    lambda: usize,
    graph: Graph,
}

pub struct Proof {}

pub struct DrgPoRep {}

impl DrgPoRep {
    pub fn new() -> DrgPoRep {
        DrgPoRep {}
    }
}

impl<'a> ProofScheme<'a> for DrgPoRep {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let graph = Graph::new(sp.drg.n, Some(Sampling::Bucket(sp.drg.m)));

        Ok(PublicParams {
            lambda: sp.lambda,
            graph: graph,
        })
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        unimplemented!();
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        unimplemented!();
    }
}

impl<'a> PoRep<'a> for DrgPoRep {
    fn replicate(
        pp: &PublicParams,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(porep::Tau, porep::ProverAux)> {
        let tree_d = pp.graph.merkle_tree(data, pp.lambda);
        let comm_d = pp.graph.commit(data, pp.lambda);

        vde::encode(&pp.graph, pp.lambda, prover_id, data);

        let tree_r = pp.graph.merkle_tree(data, pp.lambda);
        let comm_r = pp.graph.commit(data, pp.lambda);
        Ok((
            porep::Tau::new(comm_d, comm_r),
            porep::ProverAux::new(tree_d, tree_r),
        ))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        Ok(vde::decode(&pp.graph, pp.lambda, prover_id, data))
    }

    fn extract(pp: &PublicParams, prover_id: &[u8], data: &[u8], node: usize) -> Result<Vec<u8>> {
        unimplemented!()
    }
}


#[test]
fn test_setup() {
    let lambda = 16;
    let prover_id = vec![1u8; 16];
    let data = vec![2u8; 16 * 3];
    // create a copy, so we can compare roundtrips
    let mut data_copy = data.clone();
    let challenge = 1;

    let sp = SetupParams {
        lambda: lambda,
        drg: DrgParams {
            n: data.len() / lambda,
            m: 10,
        },
    };

    let pp = DrgPoRep::setup(&sp).unwrap();

    let (tau, aux) = DrgPoRep::replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice())
        .unwrap();

    assert_ne!(data, data_copy);

    let decoded_data = DrgPoRep::extract_all(&pp, prover_id.as_slice(), data_copy.as_mut_slice())
        .unwrap();

    assert_eq!(data, decoded_data);
}
