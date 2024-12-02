pub mod graph;

#[cfg(feature = "build-witness")]
pub mod generate;

use std::collections::HashMap;

use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::graph::Node;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HashSignalInfo {
    pub hash: u64,
    pub signalid: u64,
    pub signalsize: u64,
}

pub struct Graph {
    pub nodes: Vec<Node>,
    pub signals: Vec<usize>,
    pub input_mapping: Vec<HashSignalInfo>,
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
    let (nodes, signals, input_mapping): (Vec<Node>, Vec<usize>, Vec<HashSignalInfo>) =
        postcard::from_bytes(graph_bytes)?;

    Ok(Graph {
        nodes,
        signals,
        input_mapping,
    })
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
        let h = fnv1a(key);
        let mapping = &graph
            .input_mapping
            .iter()
            .find(|item| item.hash == h)
            .ok_or_else(|| eyre::eyre!("Signal not found for key: {}", key))?;

        if values.len() as u64 != mapping.signalsize {
            return Err(eyre::eyre!(
                "Mismatch in signal size for key '{}': expected {}, got {}",
                key,
                mapping.signalsize,
                values.len()
            ));
        }

        let si = mapping.signalid as usize;
        inputs_buffer[si..si + values.len()].copy_from_slice(values);
    }

    Ok(graph::evaluate(
        &graph.nodes,
        &inputs_buffer,
        &graph.signals,
    ))
}
