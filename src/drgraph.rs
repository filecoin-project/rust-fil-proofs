use std::collections::HashMap;
use std::cmp;
use rand::{Rng, thread_rng};

pub struct Graph {
    nodes: usize,
    pred: HashMap<usize, Vec<usize>>,
}

pub enum Sampling {
    DR,
    Bucket(usize),
}

impl Graph {
    // Creates a new graph. If no sampling is passed, it does not contain
    // any edges.
    pub fn new(nodes: usize, sampling: Option<Sampling>) -> Graph {
        match sampling {
            Some(Sampling::DR) => dr_sample(nodes),
            Some(Sampling::Bucket(m)) => bucket_sample(nodes, m),
            None => {
                Graph {
                    nodes: nodes,
                    // TODO: use int optimized hash function
                    // TODO: estimate capacity based on nodes
                    pred: HashMap::new(),
                }
            }
        }
    }

    // Inserts a directed edge from u -> v.
    pub fn add_edge(&mut self, u: usize, v: usize) {
        self.pred.entry(u).or_insert(Vec::new());
        if let Some(edges) = self.pred.get_mut(&u) {
            edges.push(v);
        }
    }

    // Returns the expected size of all nodes in the graph.
    pub fn expected_size(&self, node_size: usize) -> usize {
        self.nodes * node_size
    }
}

fn dr_sample(n: usize) -> Graph {
    assert!(n > 1, "graph too small");

    let mut graph = Graph::new(n, None);

    graph.add_edge(2, 1);

    for v in 3..graph.nodes {
        graph.add_edge(v, v - 1);
        graph.add_edge(v, get_random_parent(v));
    }

    graph
}


fn get_random_parent(v: usize) -> usize {
    let mut rng = thread_rng();
    let j: usize = rng.gen_range(1, floor_log2(v) + 1);
    let g = cmp::min(v - 1, 2_usize.pow(j as u32));
    println!("{} {} {} {}", g / 2, v, j, g);
    let min = cmp::max(g / 2, 2);
    let r = if min == g { min } else { rng.gen_range(min, g) };

    v - r
}

#[inline]
fn floor_log2(i: usize) -> usize {
    ((i as f64).log2() + 0.5).floor() as usize
}

fn bucket_sample(n: usize, m: usize) -> Graph {
    let g_dash = dr_sample(n * m);

    let mut graph = Graph::new(n, None);

    let mut cache: HashMap<(usize, usize), bool> = HashMap::new();
    let size = g_dash.nodes + 1;

    for v in 1..size {
        if let Some(edges) = g_dash.pred.get(&v) {
            for u in edges {
                let i = ((u - 1) / m) + 1;
                let j = ((v - 1) / m) + 1;

                let cache_hit = {
                    let cache_entry = cache.get(&(i, j));
                    if let Some(c) = cache_entry { *c } else { false }
                };
                if i != j && !cache_hit {
                    cache.insert((j, i), true);
                    graph.add_edge(j, i);
                }
            }
        }
    }

    // reorder
    for v in 1..size {
        if let Some(edges) = graph.pred.get_mut(&v) {
            edges.sort();
        }
    }

    graph
}

#[test]
fn test_graph_dr_sampling() {
    let g = Graph::new(10, Some(Sampling::DR));
    assert_eq!(g.nodes, 10);

    assert_eq!(g.pred.len(), 8);
}

#[test]
fn test_graph_bucket_sampling() {
    let g = Graph::new(10, Some(Sampling::Bucket(3)));
    assert_eq!(g.nodes, 10);
}

#[test]
fn test_graph_add_edge() {
    let mut g = Graph::new(10, None);

    g.add_edge(1, 2);
    g.add_edge(1, 3);

    let edges1 = g.pred.get(&1).unwrap();
    assert_eq!(*edges1, vec![2, 3]);

    assert_eq!(g.pred.get(&2), None);
    assert_eq!(g.pred.get(&3), None);
}
