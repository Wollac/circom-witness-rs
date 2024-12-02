use ruint::aliases::U256;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::{fs, vec};
use tempfile::tempdir;
use witness::{calculate_witness, init_graph};

#[cfg(feature = "build-witness")]
#[test]
fn generate_witness() {
    witness::generate::build_witness().unwrap();

    let circuit_file = Path::new(env!("WITNESS_CPP"));
    let circuit_name = circuit_file.file_stem().unwrap().to_str().unwrap();

    let bytes = std::fs::read("graph.bin").unwrap();

    let input = HashMap::from([
        //("age".to_string(), vec![U256::from(40)])
        (
            "in".to_string(),
            vec![U256::from(2), U256::from(3), U256::from(5)],
        ),
        //("a".to_string(), vec![U256::from(2)]),
        //("b".to_string(), vec![U256::from(3)]),
        //("c".to_string(), vec![U256::from(5)]),
    ]);

    let graph = init_graph(&bytes).unwrap();
    let witnesses = calculate_witness(&input, &graph).unwrap();

    let temp_dir = tempdir().unwrap();
    let input_file = temp_dir.path().join("input.json");
    let wtns_file = temp_dir.path().join("output.wtns");

    let json = serde_json::to_string(&input).unwrap();
    fs::write(&input_file, json).unwrap();

    let status = Command::new("node")
        .arg(format!(
            "{}/{}_js/generate_witness.js",
            env!("OUT_DIR"),
            circuit_name
        ))
        .arg(format!(
            "{}/{}_js/{}.wasm",
            env!("OUT_DIR"),
            circuit_name,
            circuit_name
        ))
        .arg(&input_file)
        .arg(&wtns_file)
        .status()
        .unwrap();
    assert!(status.success());

    let output_file = temp_dir.path().join("output.json");
    Command::new("node")
        .arg("./snarkjs")
        .arg("wej")
        .arg(&wtns_file)
        .arg(&output_file)
        .status()
        .unwrap();

    let expected: Vec<U256> =
        serde_json::from_str(&fs::read_to_string(&output_file).unwrap()).unwrap();
    assert_eq!(witnesses, expected);
}
