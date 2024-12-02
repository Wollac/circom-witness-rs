#![allow(non_snake_case)]

mod field;

use crate::graph::{self};
use crate::HashSignalInfo;
use ark_bn254::Fr;
use byteorder::{LittleEndian, ReadBytesExt};
use ffi::InputOutputList;
use field::*;
use ruint::{aliases::U256, uint};
use std::{io::Read, time::Instant};

#[cxx::bridge]
mod ffi {
    #[derive(Debug, Default, Clone)]
    pub struct InputOutputList {
        pub defs: Vec<IODef>,
    }

    #[derive(Debug, Clone, Default)]
    pub struct IODef {
        pub code: usize,
        pub offset: usize,
        pub lengths: Vec<usize>,
    }

    #[derive(Debug, Default, Clone)]
    struct Circom_Component {
        templateId: u64,
        signalStart: u64,
        inputCounter: u64,
        templateName: String,
        componentName: String,
        idFather: u64,
        subcomponents: Vec<u32>,
        outputIsSet: Vec<bool>,
    }

    #[derive(Debug)]
    struct Circom_CalcWit {
        signalValues: Vec<FrElement>,
        componentMemory: Vec<Circom_Component>,
        circuitConstants: Vec<FrElement>,
        templateInsId2IOSignalInfoList: Vec<InputOutputList>,
        listOfTemplateMessages: Vec<String>,
    }

    // Rust types and signatures exposed to C++.
    extern "Rust" {
        type FrElement;

        fn create_vec(len: usize) -> Vec<FrElement>;
        fn create_vec_u32(len: usize) -> Vec<u32>;
        fn generate_position_array(
            prefix: String,
            dimensions: Vec<u32>,
            size_dimensions: u32,
            index: u32,
        ) -> String;

        // Field operations
        unsafe fn Fr_copy(to: *mut FrElement, a: *const FrElement);
        unsafe fn Fr_copyn(to: *mut FrElement, a: *const FrElement, n: usize);
        unsafe fn Fr_add(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_sub(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_neg(to: *mut FrElement, a: *const FrElement);
        unsafe fn Fr_mul(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_inv(to: *mut FrElement, a: *const FrElement);
        unsafe fn Fr_div(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_idiv(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_mod(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_pow(to: &mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_square(to: *mut FrElement, a: *const FrElement);
        unsafe fn Fr_band(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_bor(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_bxor(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        // unsfafe fn Fr_bnot(to: &mut FrElement, a: &FrElement);
        unsafe fn Fr_shl(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_shr(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_eq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_neq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_lt(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_gt(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_leq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_geq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_land(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_lor(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        // unsafe fn Fr_lnot(to: *mut FrElement, a: *const FrElement);

        unsafe fn Fr_isTrue(a: *mut FrElement) -> bool;
        // fn Fr_fromBool(to: &mut FrElement, a: bool);
        unsafe fn Fr_toInt(a: *mut FrElement) -> u64;
    }

    // C++ types and signatures exposed to Rust.
    unsafe extern "C++" {
        include!("witness/include/witness.h");

        unsafe fn run(ctx: *mut Circom_CalcWit);
        fn get_size_of_io_map() -> u32;
        fn get_total_signal_no() -> u32;
        fn get_main_input_signal_no() -> u32;
        fn get_main_input_signal_start() -> u32;
        fn get_number_of_components() -> u32;
        fn get_size_of_constants() -> u32;
        fn get_size_of_input_hashmap() -> u32;
        fn get_size_of_witness() -> u32;
    }
}

const DAT_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/constants.dat"));

pub fn get_input_hash_map() -> Vec<HashSignalInfo> {
    let mut bytes = &DAT_BYTES[..];

    (0..ffi::get_size_of_input_hashmap())
        .map(|_| HashSignalInfo {
            hash: bytes.read_u64::<LittleEndian>().unwrap(),
            signalid: bytes.read_u64::<LittleEndian>().unwrap(),
            signalsize: bytes.read_u64::<LittleEndian>().unwrap(),
        })
        .collect()
}

pub fn get_witness_to_signal() -> Vec<usize> {
    let mut bytes = &DAT_BYTES[(ffi::get_size_of_input_hashmap() as usize) * 24..];

    (0..ffi::get_size_of_witness())
        .map(|_| {
            let si = bytes.read_u64::<LittleEndian>().unwrap();
            si.try_into().unwrap()
        })
        .collect()
}

pub fn get_constants() -> Vec<FrElement> {
    let mut bytes = &DAT_BYTES[(ffi::get_size_of_input_hashmap() as usize) * 24
        + (ffi::get_size_of_witness() as usize) * 8..];

    (0..ffi::get_size_of_constants() as usize)
        .map(|_| {
            let shortVal = bytes.read_i32::<LittleEndian>().unwrap();
            let typ = bytes.read_u32::<LittleEndian>().unwrap();

            let mut longVal = [0; 32];
            bytes.read_exact(&mut longVal).unwrap();

            if typ & 0x80000000 != 0 {
                if typ & 0x40000000 != 0 {
                    field::constant(U256::from_le_bytes(longVal).mul_redc(
                        uint!(1_U256),
                        M,
                        Fr::INV,
                    ))
                } else {
                    field::constant(U256::from_le_bytes(longVal))
                }
            } else {
                if shortVal >= 0 {
                    field::constant(U256::from(shortVal))
                } else {
                    field::constant(M - U256::from(-shortVal))
                }
            }
        })
        .collect()
}

pub fn get_iosignals() -> Vec<InputOutputList> {
    if ffi::get_size_of_io_map() == 0 {
        return vec![];
    }

    // skip the first part
    let mut bytes = &DAT_BYTES[(ffi::get_size_of_input_hashmap() as usize) * 24
        + (ffi::get_size_of_witness() as usize) * 8
        + (ffi::get_size_of_constants() as usize * 40)..];
    let io_size = ffi::get_size_of_io_map() as usize;
    let hashmap_size = ffi::get_size_of_input_hashmap() as usize;
    let mut indices = vec![0usize; io_size];
    let mut map: Vec<InputOutputList> = vec![InputOutputList::default(); hashmap_size];

    (0..io_size).for_each(|i| {
        let t32 = bytes.read_u32::<LittleEndian>().unwrap() as usize;
        indices[i] = t32;
    });

    (0..io_size).for_each(|i| {
        let l32 = bytes.read_u32::<LittleEndian>().unwrap() as usize;
        let mut io_list: InputOutputList = InputOutputList { defs: vec![] };

        (0..l32).for_each(|_j| {
            let offset = bytes.read_u32::<LittleEndian>().unwrap() as usize;
            let len = bytes.read_u32::<LittleEndian>().unwrap() as usize + 1;

            let mut lengths = vec![0usize; len];

            (1..len).for_each(|k| {
                lengths[k] = bytes.read_u32::<LittleEndian>().unwrap() as usize;
            });

            io_list.defs.push(ffi::IODef {
                code: 0,
                offset,
                lengths,
            });
        });
        map[indices[i] % hashmap_size] = io_list;
    });
    map
}

/// Run cpp witness generator and optimize graph
pub fn build_witness() -> eyre::Result<()> {
    let mut signal_values = vec![field::undefined(); ffi::get_total_signal_no() as usize];
    signal_values[0] = *field::ONE;
    for i in 0..ffi::get_main_input_signal_no() {
        let si = (ffi::get_main_input_signal_start() + i) as usize;
        signal_values[si] = field::input(si, U256::ZERO);
    }

    let mut ctx = ffi::Circom_CalcWit {
        signalValues: signal_values,
        componentMemory: vec![
            ffi::Circom_Component::default();
            ffi::get_number_of_components() as usize
        ],
        circuitConstants: get_constants(),
        templateInsId2IOSignalInfoList: get_iosignals(),
        listOfTemplateMessages: vec![],
    };

    // measure time
    let now = Instant::now();
    unsafe {
        ffi::run(&mut ctx as *mut _);
    }
    eprintln!("Generation took: {:?}", now.elapsed());

    let signal_values = get_witness_to_signal();
    let mut signals = signal_values
        .into_iter()
        .map(|i| ctx.signalValues[i].0)
        .collect::<Vec<_>>();
    let mut nodes = field::get_graph();
    eprintln!("Graph with {} nodes", nodes.len());

    // Optimize graph
    graph::optimize(&mut nodes, &mut signals);
    eprintln!("Graph with {} nodes", nodes.len());

    // Print graph
    // for (i, node) in nodes.iter().enumerate() {
    //    println!("node[{}] = {:?}", i, node);
    // }

    // Store graph to file.
    let input_map = get_input_hash_map();
    let bytes = postcard::to_stdvec(&(&nodes, &signals, &input_map)).unwrap();
    eprintln!("Graph size: {} bytes", bytes.len());
    std::fs::write("graph.bin", &bytes).unwrap();

    // Evaluate the graph.
    let input_len = (ffi::get_main_input_signal_no() + ffi::get_main_input_signal_start()) as usize; // TODO: fetch from file
    let mut inputs = vec![U256::from(0); input_len];
    inputs[0] = U256::from(1);

    let now = Instant::now();
    for _ in 0..10 {
        _ = graph::evaluate(&nodes, &inputs, &signals);
    }
    eprintln!("Calculation took: {:?}", now.elapsed() / 10);

    Ok(())
}
