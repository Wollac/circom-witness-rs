use std::{env, path::Path, process::Command};

fn main() {
    if cfg!(feature = "build-witness") {
        let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
        let out_dir = env::var_os("OUT_DIR").unwrap();
        let witness_cpp = env::var_os("WITNESS_CPP").expect("WITNESS_CPP not set");

        let circuit_file = Path::new(&witness_cpp);
        let circuit_name = circuit_file
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("Invalid circuit file name");

        let status = Command::new("circom")
            .arg(circuit_file)
            .arg("-o")
            .arg(&out_dir)
            .arg("-c")
            .arg("--wasm")
            .status()
            .unwrap();
        assert!(status.success());

        let cpp_file = Path::new(&out_dir)
            .join(format!("{circuit_name}_cpp"))
            .join(format!("{circuit_name}.cpp"));
        let script_file = Path::new(&manifest_dir).join("script/replace.sh");

        let status = Command::new(&script_file)
            .current_dir(&out_dir)
            .arg(cpp_file)
            .status()
            .unwrap();
        assert!(status.success());

        let cxx_file = Path::new(&out_dir).join("circuit.cc");
        cxx_build::bridge("src/generate/mod.rs")
            .file(&cxx_file)
            .std("c++14")
            .warnings(false)
            .opt_level(0) // for large circuits, compile time is infeasible with optimization
            .compile("witness");

        println!("cargo::rerun-if-changed=build.rs");
        println!("cargo::rerun-if-changed=src/generate");
        println!("cargo::rerun-if-env-changed=WITNESS_CPP");
    }
}
