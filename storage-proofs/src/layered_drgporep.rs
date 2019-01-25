use std::sync::mpsc::channel;

use crossbeam_utils::thread;
use rayon::prelude::*;
use serde::de::Deserialize;
use serde::ser::Serialize;
use slog::*;

use crate::challenge_derivation::derive_challenges;
use crate::drgporep::{self, DrgPoRep};
use crate::drgraph::Graph;
use crate::error::{Error, Result};
use crate::hasher::{Domain, HashFunction, Hasher};
use crate::merkle::MerkleTree;
use crate::parameter_cache::ParameterSetIdentifier;
use crate::porep::{self, PoRep};
use crate::proof::ProofScheme;
use crate::vde;
use crate::SP_LOG;

#[derive(Debug)]
pub struct SetupParams {
    pub drg_porep_setup_params: drgporep::SetupParams,
    pub layers: usize,
    pub challenge_count: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetIdentifier,
{
    pub drg_porep_public_params: drgporep::PublicParams<H, G>,
    pub layers: usize,
    pub challenge_count: usize,
}

#[derive(Clone)]
pub struct Tau<T: Domain> {
    pub layer_taus: Vec<porep::Tau<T>>,
    pub comm_r_star: T,
}

impl<T: Domain> Tau<T> {
    /// Return a single porep::Tau with the initial data and final replica commitments of layer_taus.
    pub fn simplify(&self) -> porep::Tau<T> {
        porep::Tau {
            comm_r: self.layer_taus[self.layer_taus.len() - 1].comm_r,
            comm_d: self.layer_taus[0].comm_d,
        }
    }
}

impl<H, G> ParameterSetIdentifier for PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetIdentifier,
{
    fn parameter_set_identifier(&self) -> String {
        format!(
            "layered_drgporep::PublicParams{{ drg_porep_identifier: {}, layers: {}, challenge_count: {} }}",
            self.drg_porep_public_params.parameter_set_identifier(),
            self.layers,
            self.challenge_count,
        )
    }
}

impl<'a, H, G> From<&'a PublicParams<H, G>> for PublicParams<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetIdentifier,
{
    fn from(pp: &PublicParams<H, G>) -> PublicParams<H, G> {
        PublicParams {
            drg_porep_public_params: pp.drg_porep_public_params.clone(),
            layers: pp.layers,
            challenge_count: pp.challenge_count,
        }
    }
}

pub type EncodingProof<H> = drgporep::Proof<H>;

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    pub replica_id: T,
    pub challenge_count: usize,
    pub tau: Option<porep::Tau<T>>,
    pub comm_r_star: T,
    pub k: Option<usize>,
}

impl<T: Domain> PublicInputs<T> {
    pub fn challenges(&self, leaves: usize, layer: u8, partition_k: Option<usize>) -> Vec<usize> {
        derive_challenges::<T>(
            self.challenge_count,
            layer,
            leaves,
            &self.replica_id,
            &self.comm_r_star,
            partition_k.unwrap_or(0) as u8,
        )
    }
}

pub struct PrivateInputs<'a, H: Hasher> {
    pub replica: &'a [u8],
    pub aux: Vec<MerkleTree<H::Domain, H::Function>>,
    pub tau: Vec<porep::Tau<H::Domain>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "EncodingProof<H>: Serialize",
        deserialize = "EncodingProof<H>: Deserialize<'de>"
    ))]
    pub encoding_proofs: Vec<EncodingProof<H>>,
    pub tau: Vec<porep::Tau<H::Domain>>,
}

impl<H: Hasher> Proof<H> {
    pub fn serialize(&self) -> Vec<u8> {
        unimplemented!();
    }
}

pub type PartitionProofs<H> = Vec<Proof<H>>;

impl<H: Hasher> Proof<H> {
    pub fn new(
        encoding_proofs: Vec<EncodingProof<H>>,
        tau: Vec<porep::Tau<H::Domain>>,
    ) -> Proof<H> {
        Proof {
            encoding_proofs,
            tau,
        }
    }
}

pub trait Layerable<H: Hasher>: Graph<H> {}

/// Layers provides default implementations of methods required to handle proof and verification
/// of layered proofs of replication. Implementations must provide transform and invert_transform methods.
pub trait Layers {
    type Hasher: Hasher;
    type Graph: Layerable<Self::Hasher> + ParameterSetIdentifier + Sync + Send;

    /// transform a layer's public parameters, returning new public parameters corresponding to the next layer.
    fn transform(
        pp: &drgporep::PublicParams<Self::Hasher, Self::Graph>,
        layer: usize,
        layers: usize,
    ) -> drgporep::PublicParams<Self::Hasher, Self::Graph>;

    /// transform a layer's public parameters, returning new public parameters corresponding to the previous layer.
    fn invert_transform(
        pp: &drgporep::PublicParams<Self::Hasher, Self::Graph>,
        layer: usize,
        layers: usize,
    ) -> drgporep::PublicParams<Self::Hasher, Self::Graph>;

    fn prove_layers<'a>(
        pp: &drgporep::PublicParams<Self::Hasher, Self::Graph>,
        pub_inputs: &PublicInputs<<Self::Hasher as Hasher>::Domain>,
        tau: &[porep::Tau<<Self::Hasher as Hasher>::Domain>],
        aux: &'a [MerkleTree<
            <Self::Hasher as Hasher>::Domain,
            <Self::Hasher as Hasher>::Function,
        >],
        layers: usize,
        total_layers: usize,
        partition_count: usize,
    ) -> Result<Vec<Vec<EncodingProof<Self::Hasher>>>> {
        assert!(layers > 0);

        let mut new_pp = None;

        (0..layers)
            .map(|layer| {
                let pp = match new_pp {
                    Some(ref new_pp) => new_pp,
                    None => pp,
                };
                let inner_layers = layers - layer;

                let new_priv_inputs = drgporep::PrivateInputs {
                    aux: &porep::ProverAux {
                        tree_d: aux[layer].clone(),
                        tree_r: aux[layer + 1].clone(),
                    },
                };
                let layer_diff = total_layers - inner_layers;

                let partition_proofs: Vec<_> = (0..partition_count)
                    .into_par_iter()
                    .map(|k| {
                        let drgporep_pub_inputs = drgporep::PublicInputs {
                            replica_id: pub_inputs.replica_id,
                            challenges: pub_inputs.challenges(
                                pp.graph.size(),
                                layer_diff as u8,
                                Some(k),
                            ),
                            tau: Some(tau[layer]),
                        };

                        DrgPoRep::prove(pp, &drgporep_pub_inputs, &new_priv_inputs)
                    })
                    .collect::<Result<Vec<_>>>()?;

                new_pp = Some(Self::transform(pp, layer_diff, total_layers));

                Ok(partition_proofs)
            })
            .collect::<Result<Vec<_>>>()
    }

    fn extract_and_invert_transform_layers<'a>(
        drgpp: &drgporep::PublicParams<Self::Hasher, Self::Graph>,
        layers: usize,
        replica_id: &<Self::Hasher as Hasher>::Domain,
        data: &'a mut [u8],
    ) -> Result<()> {
        assert!(layers > 0);

        (0..layers).fold((*drgpp).clone(), |current_drgpp, layer| {
            let inverted = Self::invert_transform(&current_drgpp, layer, layers);
            let mut res = DrgPoRep::extract_all(&inverted, replica_id, data).unwrap();

            for (i, r) in res.iter_mut().enumerate() {
                data[i] = *r;
            }
            inverted
        });

        Ok(())
    }

    fn transform_and_replicate_layers(
        drgpp: &drgporep::PublicParams<Self::Hasher, Self::Graph>,
        layers: usize,
        replica_id: &<Self::Hasher as Hasher>::Domain,
        data: &mut [u8],
    ) -> Result<(
        Vec<porep::Tau<<Self::Hasher as Hasher>::Domain>>,
        Vec<MerkleTree<<Self::Hasher as Hasher>::Domain, <Self::Hasher as Hasher>::Function>>,
    )> {
        assert!(layers > 0);
        let mut taus = Vec::with_capacity(layers);
        let mut auxs: Vec<
            MerkleTree<<Self::Hasher as Hasher>::Domain, <Self::Hasher as Hasher>::Function>,
        > = Vec::with_capacity(layers);

        let generate_merkle_trees_in_parallel = true;
        if !generate_merkle_trees_in_parallel {
            // This branch serializes encoding and merkle tree generation.
            // However, it makes clear the underlying algorithm we reproduce
            // in the parallel case. We should keep this code for documentation and to help
            // alert us if drgporep's implementation changes (and breaks type-checking).
            // It would not be a bad idea to add tests ensuring the parallel and serial cases
            // generate the same results.
            (0..layers).fold((*drgpp).clone(), |current_drgpp, layer| {
                let previous_replica_tree = if !auxs.is_empty() {
                    auxs.last().cloned()
                } else {
                    None
                };

                let (tau, aux) =
                    DrgPoRep::replicate(&current_drgpp, replica_id, data, previous_replica_tree)
                        .unwrap();

                taus.push(tau);
                auxs.push(aux.tree_r);

                Self::transform(&current_drgpp, layer, layers)
            });
        } else {
            // The parallel case is more complicated but should produce the same results as the
            // serial case. Note that to make lifetimes work out, we have to inline and tease apart
            // the definition of DrgPoRep::replicate. This is because as implemented, it entangles
            // encoding and merkle tree generation too tightly to be used as a subcomponent.
            // Instead, we need to create a scope which encloses all the work, spawning threads
            // for merkle tree generation and sending the results back to a channel.
            // The received results need to be sorted by layer because ordering of the completed results
            // is not guaranteed. Misordered results will be seen in practice when trees are small.

            // The outer scope ensure that `tx` is dropped and closed before we read from `outer_rx`.
            // Otherwise, the read loop will block forever waiting for more input.
            let outer_rx = {
                let (tx, rx) = channel();

                let errf = |e| {
                    let err_string = format!("{:?}", e);
                    error!(SP_LOG, "MerkleTreeGenerationError"; "err" => &err_string, "backtrace" => format!("{:?}", failure::Backtrace::new()));
                    Error::MerkleTreeGenerationError(err_string)
                };

                let _ = thread::scope(|scope| -> Result<()> {
                    let mut threads = Vec::with_capacity(layers + 1);
                    let initial_pp = (*drgpp).clone();
                    (0..=layers).fold(initial_pp, |current_drgpp, layer| {
                        let mut data_copy = vec![0; data.len()];
                        data_copy[0..data.len()].clone_from_slice(data);

                        let return_channel = tx.clone();
                        let (transfer_tx, transfer_rx) =
                            channel::<drgporep::PublicParams<Self::Hasher, Self::Graph>>();

                        transfer_tx.send(current_drgpp.clone()).unwrap();

                        let thread = scope.spawn(move |_| {
                            // If we panic anywhere in this closure, thread.join() below will receive an error —
                            // so it is safe to unwrap.
                            let drgpp = transfer_rx.recv().unwrap();
                            let tree_d = drgpp.graph.merkle_tree(&data_copy).unwrap();

                            info!(SP_LOG, "returning tree"; "layer" => format!("{}", layer));
                            return_channel.send((layer, tree_d)).unwrap();
                        });

                        threads.push(thread);

                        if layer < layers {
                            info!(SP_LOG, "encoding"; "layer {}" => format!("{}", layer));
                            vde::encode(
                                &current_drgpp.graph,
                                current_drgpp.sloth_iter,
                                replica_id,
                                data,
                            )
                            .expect("encoding failed in thread");
                        }
                        Self::transform(&current_drgpp, layer, layers)
                    });

                    for thread in threads {
                        thread.join().map_err(errf)?;
                    }

                    Ok(())
                })
                .map_err(errf)?;

                rx
            };

            let sorted_trees = {
                let mut labeled_trees = outer_rx.iter().collect::<Vec<_>>();
                labeled_trees.sort_by_key(|x| x.0);
                labeled_trees
            };

            sorted_trees.iter().fold(
                None,
                |previous_tree: Option<&MerkleTree<_, _>>, (i, replica_tree)| {
                    // Each iteration's replica_tree becomes the next iteration's previous_tree (data_tree).
                    // The first iteration has no previous_tree.
                    if let Some(data_tree) = previous_tree {
                        let tau = porep::Tau {
                            comm_r: replica_tree.root(),
                            comm_d: data_tree.root(),
                        };
                        info!(SP_LOG, "setting tau/aux"; "layer" => format!("{}", i - 1));
                        taus.push(tau);
                    };
                    auxs.push(replica_tree.clone());

                    Some(replica_tree)
                },
            );
        };
        Ok((taus, auxs))
    }
}

impl<'a, L: Layers> ProofScheme<'a> for L {
    type PublicParams = PublicParams<L::Hasher, L::Graph>;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<L::Hasher as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<'a, L::Hasher>;
    type Proof = Proof<L::Hasher>;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        let dp_sp = DrgPoRep::setup(&sp.drg_porep_setup_params)?;
        let pp = PublicParams {
            drg_porep_public_params: dp_sp,
            layers: sp.layers,
            challenge_count: sp.challenge_count,
        };

        Ok(pp)
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let proofs = Self::prove_all_partitions(pub_params, pub_inputs, priv_inputs, 1)?;
        let k = match pub_inputs.k {
            None => 0,
            Some(k) => k,
        };

        Ok(proofs[k].to_owned())
    }

    fn prove_all_partitions<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
        partition_count: usize,
    ) -> Result<Vec<Self::Proof>> {
        assert!(partition_count > 0);

        let proofs = Self::prove_layers(
            &pub_params.drg_porep_public_params,
            pub_inputs,
            &priv_inputs.tau,
            &priv_inputs.aux,
            pub_params.layers,
            pub_params.layers,
            partition_count,
        )?;

        let mut proof_columns = vec![Vec::new(); partition_count];

        for partition_proofs in proofs.into_iter() {
            for (j, proof) in partition_proofs.into_iter().enumerate() {
                proof_columns[j].push(proof);
            }
        }

        let proofs = proof_columns
            .into_iter()
            .map(|p| Proof::new(p, priv_inputs.tau.clone()))
            .collect();

        Ok(proofs)
    }

    fn verify_all_partitions(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        partition_proofs: &[Self::Proof],
    ) -> Result<bool> {
        for (k, proof) in partition_proofs.iter().enumerate() {
            if proof.encoding_proofs.len() != pub_params.layers {
                return Ok(false);
            }

            let total_layers = pub_params.layers;
            let mut pp = pub_params.drg_porep_public_params.clone();
            // TODO: verification is broken for the first node, figure out how to unbreak
            // with permutations

            let mut comm_rs = Vec::new();

            for (layer, proof_layer) in proof.encoding_proofs.iter().enumerate() {
                comm_rs.push(proof.tau[layer].comm_r);

                let new_pub_inputs = drgporep::PublicInputs {
                    replica_id: pub_inputs.replica_id,
                    challenges: pub_inputs.challenges(
                        pub_params.drg_porep_public_params.graph.size(),
                        layer as u8,
                        Some(k),
                    ),
                    tau: Some(proof.tau[layer]),
                };

                let ep = &proof_layer;
                let res = DrgPoRep::verify(
                    &pp,
                    &new_pub_inputs,
                    &drgporep::Proof {
                        data_root: ep.data_root,
                        replica_root: ep.replica_root,
                        replica_nodes: ep.replica_nodes.clone(),
                        replica_parents: ep.replica_parents.clone(),
                        // TODO: investigate if clone can be avoided by using a reference in drgporep::DataProof
                        nodes: ep.nodes.clone(),
                    },
                )?;

                pp = Self::transform(&pp, layer, total_layers);

                if !res {
                    return Ok(false);
                }
            }
            let crs = comm_r_star::<L::Hasher>(&pub_inputs.replica_id, &comm_rs)?;

            if crs != pub_inputs.comm_r_star {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn with_partition(pub_in: Self::PublicInputs, k: Option<usize>) -> Self::PublicInputs {
        self::PublicInputs {
            replica_id: pub_in.replica_id,
            challenge_count: pub_in.challenge_count,
            tau: pub_in.tau,
            comm_r_star: pub_in.comm_r_star,
            k,
        }
    }
}

// We need to calculate CommR* -- which is: H(replica_id|comm_r[0]|comm_r[1]|…comm_r[n])
fn comm_r_star<H: Hasher>(replica_id: &H::Domain, comm_rs: &[H::Domain]) -> Result<H::Domain> {
    let l = (comm_rs.len() + 1) * 32;
    let mut bytes = vec![0; l];

    replica_id.write_bytes(&mut bytes[0..32])?;

    for (i, comm_r) in comm_rs.iter().enumerate() {
        comm_r.write_bytes(&mut bytes[(i + 1) * 32..(i + 2) * 32])?;
    }

    Ok(H::Function::hash(&bytes))
}

impl<'a, 'c, L: Layers> PoRep<'a, L::Hasher> for L {
    type Tau = Tau<<L::Hasher as Hasher>::Domain>;
    type ProverAux =
        Vec<MerkleTree<<L::Hasher as Hasher>::Domain, <L::Hasher as Hasher>::Function>>;

    fn replicate(
        pp: &'a PublicParams<L::Hasher, L::Graph>,
        replica_id: &<L::Hasher as Hasher>::Domain,
        data: &mut [u8],
        _data_tree: Option<
            MerkleTree<<L::Hasher as Hasher>::Domain, <L::Hasher as Hasher>::Function>,
        >,
    ) -> Result<(Self::Tau, Self::ProverAux)> {
        let (taus, auxs) = Self::transform_and_replicate_layers(
            &pp.drg_porep_public_params,
            pp.layers,
            replica_id,
            data,
        )?;

        let comm_rs: Vec<_> = taus.iter().map(|tau| tau.comm_r).collect();
        let crs = comm_r_star::<L::Hasher>(replica_id, &comm_rs)?;
        let tau = Tau {
            layer_taus: taus,
            comm_r_star: crs,
        };
        Ok((tau, auxs))
    }

    fn extract_all<'b>(
        pp: &'b PublicParams<L::Hasher, L::Graph>,
        replica_id: &'b <L::Hasher as Hasher>::Domain,
        data: &'b [u8],
    ) -> Result<Vec<u8>> {
        let mut data = data.to_vec();

        Self::extract_and_invert_transform_layers(
            &pp.drg_porep_public_params,
            pp.layers,
            replica_id,
            &mut data,
        )?;

        Ok(data)
    }

    fn extract(
        _pp: &PublicParams<L::Hasher, L::Graph>,
        _replica_id: &<L::Hasher as Hasher>::Domain,
        _data: &[u8],
        _node: usize,
    ) -> Result<Vec<u8>> {
        unimplemented!();
    }
}
