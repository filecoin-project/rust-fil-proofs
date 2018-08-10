use drgporep::{self, DrgPoRep};
use drgraph::Graph;
use error::Result;
use fr32::fr_into_bytes;
use pairing::bls12_381::{Bls12, Fr};
use porep::{self, PoRep};
use proof::ProofScheme;

#[derive(Debug)]
pub struct SetupParams {
    pub drg_porep_setup_params: drgporep::SetupParams,
    pub layers: usize,
}

#[derive(Debug)]
pub struct PublicParams<G: Graph> {
    pub drg_porep_public_params: drgporep::PublicParams<G>,
    pub layers: usize,
}

pub type ReplicaParents = Vec<(usize, DataProof)>;
pub type EncodingProof = drgporep::Proof;
pub type DataProof = drgporep::DataProof;

pub struct PublicInputs<'a> {
    pub prover_id: &'a Fr,
    pub challenge: usize,
    pub tau: Vec<porep::Tau>,
}

pub struct PrivateInputs<'a> {
    pub replica: &'a [u8],
    pub aux: &'a [porep::ProverAux],
}

#[derive(Debug, Clone)]
pub struct Proof {
    pub encoding_proofs: Vec<EncodingProof>,
}

impl Proof {
    pub fn new(encoding_proofs: Vec<EncodingProof>) -> Proof {
        Proof { encoding_proofs }
    }
}

pub trait Layerable: Graph {}

/// Layers provides default implementations of methods required to handle proof and verification
/// of layered proofs of replication. Implementations must provide transform and invert_transform methods.
pub trait Layers {
    type Graph: Layerable;

    /// transform a layer's public parameters, returning new public parameters corresponding to the next layer.
    fn transform(
        pp: &drgporep::PublicParams<Self::Graph>,
        layer: usize,
        layers: usize,
    ) -> drgporep::PublicParams<Self::Graph>;

    /// transform a layer's public parameters, returning new public parameters corresponding to the previous layer.
    fn invert_transform(
        pp: &drgporep::PublicParams<Self::Graph>,
        layer: usize,
        layers: usize,
    ) -> drgporep::PublicParams<Self::Graph>;

    fn prove_layers<'a>(
        pp: &drgporep::PublicParams<Self::Graph>,
        pub_inputs: &PublicInputs,
        priv_inputs: &drgporep::PrivateInputs,
        aux: &[porep::ProverAux],
        layers: usize,
        total_layers: usize,
        proofs: &'a mut Vec<EncodingProof>,
    ) -> Result<&'a Vec<EncodingProof>> {
        assert!(layers > 0);

        let mut scratch = priv_inputs.replica.to_vec().clone();
        let prover_id = fr_into_bytes::<Bls12>(pub_inputs.prover_id);
        <DrgPoRep<Self::Graph> as PoRep>::replicate(pp, &prover_id, scratch.as_mut_slice())?;

        let new_priv_inputs = drgporep::PrivateInputs {
            replica: scratch.as_slice(),
            aux: &aux[aux.len() - layers],
        };
        let drgporep_pub_inputs = drgporep::PublicInputs {
            prover_id: *pub_inputs.prover_id,
            challenges: vec![pub_inputs.challenge],
            tau: &pub_inputs.tau[pub_inputs.tau.len() - layers],
        };
        let drg_proof = DrgPoRep::prove(&pp, &drgporep_pub_inputs, &new_priv_inputs)?;
        proofs.push(drg_proof);

        let pp = &Self::transform(pp, total_layers - layers, total_layers);

        if layers != 1 {
            Self::prove_layers(
                pp,
                pub_inputs,
                &new_priv_inputs,
                aux,
                layers - 1,
                layers,
                proofs,
            )?;
        }

        Ok(proofs)
    }

    fn extract_and_invert_transform_layers<'a>(
        drgpp: &drgporep::PublicParams<Self::Graph>,
        layer: usize,
        layers: usize,
        prover_id: &[u8],
        data: &'a mut [u8],
    ) -> Result<()> {
        assert!(layers > 0);

        let inverted = &Self::invert_transform(&drgpp, layer, layers);
        let mut res = DrgPoRep::extract_all(inverted, prover_id, data).unwrap();

        for (i, r) in res.iter_mut().enumerate() {
            data[i] = *r;
        }

        if layers != 1 {
            Self::extract_and_invert_transform_layers(
                inverted,
                layer + 1,
                layers - 1,
                prover_id,
                data,
            )?;
        }

        Ok(())
    }

    fn transform_and_replicate_layers(
        drgpp: &drgporep::PublicParams<Self::Graph>,
        layer: usize,
        layers: usize,
        prover_id: &[u8],
        data: &mut [u8],
        taus: &mut Vec<porep::Tau>,
        auxs: &mut Vec<porep::ProverAux>,
    ) -> Result<()> {
        assert!(layers > 0);
        let (tau, aux) = DrgPoRep::replicate(drgpp, prover_id, data).unwrap();

        taus.push(tau);
        auxs.push(aux);

        if layers != 1 {
            Self::transform_and_replicate_layers(
                &Self::transform(&drgpp, layer, layers),
                layer + 1,
                layers - 1,
                prover_id,
                data,
                taus,
                auxs,
            )?;
        }

        Ok(())
    }
}

impl<'a, L: Layers> ProofScheme<'a> for L {
    type PublicParams = PublicParams<L::Graph>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let dp_sp = DrgPoRep::setup(&sp.drg_porep_setup_params)?;
        let pp = PublicParams {
            drg_porep_public_params: dp_sp,
            layers: sp.layers,
        };

        Ok(pp)
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let drg_priv_inputs = drgporep::PrivateInputs {
            aux: &priv_inputs.aux[0],
            replica: priv_inputs.replica,
        };

        let mut proofs = Vec::with_capacity(pub_params.layers);

        Self::prove_layers(
            &pub_params.drg_porep_public_params,
            pub_inputs,
            &drg_priv_inputs,
            priv_inputs.aux,
            pub_params.layers,
            pub_params.layers,
            &mut proofs,
        )?;

        Ok(Proof::new(proofs))
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        if proof.encoding_proofs.len() != pub_params.layers {
            return Ok(false);
        }

        let total_layers = pub_params.layers;
        let mut pp = pub_params.drg_porep_public_params.clone();
        // TODO: verification is broken for the first node, figure out how to unbreak
        // with permuations
        for (layer, proof_layer) in proof.encoding_proofs.iter().enumerate() {
            let new_pub_inputs = drgporep::PublicInputs {
                prover_id: *pub_inputs.prover_id,
                challenges: vec![pub_inputs.challenge],
                tau: &pub_inputs.tau[layer],
            };

            let ep = &proof_layer;
            let parents: Vec<_> = ep
                .replica_parents[0]
                .iter()
                .map(|p| {
                    (
                        p.0,
                        drgporep::DataProof {
                            // TODO: investigate if clone can be avoided by using a reference in drgporep::DataProof
                            proof: p.1.proof.clone(),
                            data: p.1.data,
                        },
                    )
                })
                .collect();

            let res = DrgPoRep::verify(
                &pp,
                &new_pub_inputs,
                &drgporep::Proof {
                    replica_nodes: vec![drgporep::DataProof {
                        // TODO: investigate if clone can be avoided by using a reference in drgporep::DataProof
                        proof: ep.replica_nodes[0].proof.clone(),
                        data: ep.replica_nodes[0].data,
                    }],
                    replica_parents: vec![parents],
                    // TODO: investigate if clone can be avoided by using a reference in drgporep::DataProof
                    nodes: vec![ep.nodes[0].clone()],
                },
            )?;

            pp = Self::transform(&pp, layer, total_layers);

            if !res {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl<'a, 'c, L: Layers> PoRep<'a> for L {
    type Tau = Vec<porep::Tau>;
    type ProverAux = Vec<porep::ProverAux>;

    fn replicate(
        pp: &'a PublicParams<L::Graph>,
        prover_id: &[u8],
        data: &mut [u8],
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let mut taus = Vec::with_capacity(pp.layers);
        let mut auxs = Vec::with_capacity(pp.layers);

        Self::transform_and_replicate_layers(
            &pp.drg_porep_public_params,
            0,
            pp.layers,
            prover_id,
            data,
            &mut taus,
            &mut auxs,
        )?;

        Ok((taus, auxs))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<L::Graph>,
        prover_id: &'b [u8],
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        Self::extract_and_invert_transform_layers(
            &pp.drg_porep_public_params,
            0,
            pp.layers,
            prover_id,
            &mut data,
        )?;

        Ok(data)
    }

    fn extract(
        _pp: &PublicParams<L::Graph>,
        _prover_id: &[u8],
        _data: &[u8],
        _node: usize,
    ) -> Result<Vec<u8>> {
        unimplemented!();
    }
}
