pub mod graph;

#[cfg(feature = "build-witness")]
pub mod generate;

use crate::graph::Node;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSignalInfo {
    /// Unique identifier of the first corresponding signal.
    pub id: usize,
    /// Number of corresponding consecutive signals.
    pub size: usize,
}

/// Represents the computational graph structure of a witness generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Graph {
    /// The nodes forming the abstract syntax tree (AST) of the graph.
    pub nodes: Vec<Node>,
    /// Maps each output to the index of its corresponding node in the `nodes` vector.
    pub outputs: Vec<usize>,
    /// Maps each input signal to its corresponding SignalInfo.
    /// The key is the FNV-1a hash of the input's name for efficient lookup.
    pub input_map: HashMap<u64, InputSignalInfo>,
}

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for c in s.bytes() {
        hash ^= c as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

/// Loads the graph from bytes
pub fn init_graph(graph_bytes: &[u8]) -> eyre::Result<Graph> {
    let graph = postcard::from_bytes(graph_bytes)?;

    Ok(graph)
}

/// Calculates the number of needed inputs
pub fn get_inputs_size(graph: &Graph) -> usize {
    let mut start = false;
    let mut max_index = 0usize;
    for &node in graph.nodes.iter() {
        if let Node::Input(i) = node {
            if i > max_index {
                max_index = i;
            }
            start = true
        } else if start {
            break;
        }
    }
    max_index + 1
}

/// Calculate witness based on serialized graph and inputs
pub fn calculate_witness(
    input_list: &HashMap<String, Vec<U256>>,
    graph: &Graph,
) -> eyre::Result<Vec<U256>> {
    let mut inputs_buffer = vec![U256::ZERO; get_inputs_size(graph)];

    for (key, values) in input_list {
        let hash = fnv1a(key);
        let signal = graph
            .input_map
            .get(&hash)
            .ok_or_else(|| eyre::eyre!("Signal not found for key: {}", key))?;

        if values.len() != signal.size {
            return Err(eyre::eyre!(
                "Mismatch in signal size for key '{}': expected {}, got {}",
                key,
                signal.size,
                values.len()
            ));
        }

        inputs_buffer[signal.id..signal.id + values.len()].copy_from_slice(values);
    }

    Ok(graph::evaluate(
        &graph.nodes,
        &inputs_buffer,
        &graph.outputs,
    ))
}
