
use porep::{self, PoRep};
use drgraph::{Graph, Sampling};
use vde;

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

pub struct DrgPoRep {}

impl DrgPoRep {
    pub fn new() -> DrgPoRep {
        DrgPoRep {}
    }

    pub fn setup(&self, sp: &SetupParams) -> PublicParams {
        let graph = Graph::new(sp.drg.n, Some(Sampling::Bucket(sp.drg.m)));

        PublicParams {
            lambda: sp.lambda,
            graph: graph,
        }
    }
}

impl PoRep<PublicParams> for DrgPoRep {
    fn replicate<'a>(
        &self,
        pp: &'a PublicParams,
        prover_id: &'a [u8],
        data: &'a mut [u8],
    ) -> (porep::Tau, porep::ProverAux) {
        let tree_d = pp.graph.merkle_tree(data, pp.lambda);
        let comm_d = pp.graph.commit(data, pp.lambda);

        vde::encode(&pp.graph, pp.lambda, prover_id, data);

        let tree_r = pp.graph.merkle_tree(data, pp.lambda);
        let comm_r = pp.graph.commit(data, pp.lambda);
        (
            porep::Tau::new(comm_d, comm_r),
            porep::ProverAux::new(tree_d, tree_r),
        )
    }

    fn extract_all<'a, 'b>(
        &'a self,
        pp: &'b PublicParams,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> &'b [u8] {
        unimplemented!()
    }

    fn extract<'a>(
        &'a self,
        pp: &'a PublicParams,
        prover_id: &'a [u8],
        data: &'a [u8],
        node: usize,
    ) -> &'a [u8] {
        unimplemented!()
    }
}


#[test]
fn test_setup() {
    let lambda = 16;
    let prover_id = vec![1u8; 16];
    let data = vec![2u8; 16 * 3];
    let mut data_copy = data.clone();
    let challenge = 1;

    let sp = SetupParams {
        lambda: lambda,
        drg: DrgParams {
            n: data.len() / lambda,
            m: 10,
        },
    };

    let dp = DrgPoRep::new();
    let pp = dp.setup(&sp);

    let (tau, aux) = dp.replicate(&pp, prover_id.as_slice(), data_copy.as_mut_slice());
}
