use crate::graph::{Node, Operation};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ruint::{aliases::U256, uint};
use std::{
    ptr,
    sync::{LazyLock, Mutex},
};

/// The modulus of the field.
pub const M: U256 = U256::from_limbs(Fr::MODULUS.0);

static NODES: Mutex<Vec<Node>> = Mutex::new(Vec::new());
static VALUES: Mutex<Vec<U256>> = Mutex::new(Vec::new());
static CONSTANT: Mutex<Vec<bool>> = Mutex::new(Vec::new());

pub static ZERO: LazyLock<FrElement> = LazyLock::new(|| constant(U256::ZERO));
pub static ONE: LazyLock<FrElement> = LazyLock::new(|| constant(uint!(1_U256)));

#[derive(Debug, Default, Clone, Copy)]
pub struct FrElement(pub usize);

pub fn print_eval() {
    let nodes = NODES.lock().unwrap();
    let values = VALUES.lock().unwrap();
    let constant = CONSTANT.lock().unwrap();

    let mut constants = 0_usize;
    for (i, node) in nodes.iter().enumerate() {
        print!("{}: {:?}", i, node);
        if constant[i] {
            constants += 1;
            println!(" = {}", values[i]);
        } else {
            println!();
        }
    }
    eprintln!(
        "{} nodes of which {} constant and {} dynamic",
        nodes.len(),
        constants,
        nodes.len() - constants
    );
}

pub fn trace(r: usize, nodes: &[Node]) -> Vec<(usize, &Node)>{
    let n = &nodes[r];
    match n {
        Node::Input(_) => vec![(r,n)],
        Node::Constant(_) => vec![(r,n)],
        Node::MontConstant(_) => vec![(r,n)],
        Node::Op(_, a, b) => [trace(*a, nodes), trace(*b, nodes), vec![(r,n)]].concat(),
    }
}

pub fn get_graph() -> Vec<Node> {
    NODES.lock().unwrap().clone()
}

pub fn get_values() -> Vec<U256> {
    VALUES.lock().unwrap().clone()
}

pub const fn undefined() -> FrElement {
    FrElement(usize::MAX)
}

pub fn constant(value: U256) -> FrElement {
    assert!(value < M);

    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    nodes.push(Node::Constant(value));
    values.push(value);
    constant.push(true);

    FrElement(nodes.len() - 1)
}

pub fn input(signal_id: usize, value: U256) -> FrElement {
    assert!(value < M);

    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    nodes.push(Node::Input(signal_id));
    values.push(value);
    constant.push(false);

    FrElement(nodes.len() - 1)
}

fn binop(op: Operation, to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let (a, b, to) = unsafe { ((*a).0, (*b).0, &mut (*to).0) };
    assert!(a < nodes.len());
    assert!(b < nodes.len());
    nodes.push(Node::Op(op, a, b));
    *to = nodes.len() - 1;

    let (va, vb) = (values[a], values[b]);
    let value = op.eval(va, vb);
    debug_assert!(value < M);
    values.push(value);

    let (ca, cb) = (constant[a], constant[b]);
    constant.push(ca && cb);
}

pub unsafe fn Fr_mul(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Mul, to, a, b);
}

pub unsafe fn Fr_add(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Add, to, a, b);
}

pub unsafe fn Fr_sub(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Sub, to, a, b);
}

pub unsafe fn Fr_neg(to: *mut FrElement, a: *const FrElement) {
    // evaluate as binary operation
    binop(Operation::Sub, to, &*ZERO, a);
}

pub unsafe fn Fr_inv(to: *mut FrElement, a: *const FrElement) {
    // evaluate as binary operation
    binop(Operation::Div, to, &*ONE, a);
}

pub unsafe fn Fr_div(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Div, to, a, b);
}

pub unsafe fn Fr_idiv(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Idiv, to, a, b);
}

pub unsafe fn Fr_mod(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Mod, to, a, b);
}

pub unsafe fn Fr_pow(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Pow, to, a, b);
}

pub unsafe fn Fr_square(to: *mut FrElement, a: *const FrElement) {
    binop(Operation::Mul, to, a, a);
}

pub unsafe fn Fr_copy(to: *mut FrElement, a: *const FrElement) {
    *to = *a;
}

pub unsafe fn Fr_copyn(to: *mut FrElement, a: *const FrElement, n: usize) {
    ptr::copy_nonoverlapping(a, to, n);
}

/// Create a vector of FrElement with length `len`.
/// Needed because the default constructor of opaque type is not implemented.
pub fn create_vec(len: usize) -> Vec<FrElement> {
    vec![FrElement(usize::MAX); len]
}

pub fn create_vec_u32(len: usize) -> Vec<u32> {
    vec![0; len]
}

pub fn generate_position_array(
    prefix: String,
    dimensions: Vec<u32>,
    size_dimensions: u32,
    index: u32,
) -> String {
    let mut positions: String = prefix;
    let mut index = index;
    for i in 0..size_dimensions {
        let last_pos = index % dimensions[size_dimensions as usize - 1 - i as usize];
        index /= dimensions[size_dimensions as usize - 1 - i as usize];
        let new_pos = format!("[{}]", last_pos);
        positions = new_pos + &positions;
    }
    positions
}

pub unsafe fn Fr_toInt(a: *const FrElement) -> u64 {
    let nodes = NODES.lock().unwrap();
    let values = VALUES.lock().unwrap();
    let constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let a = unsafe { (*a).0 };
    assert!(a < nodes.len());
    if !constant[a] {
        eprintln!("Fr_toInt is only supported for constants");
    }
    values[a].try_into().unwrap()
}

pub unsafe fn Fr_isTrue(a: *mut FrElement) -> bool {
    let nodes = NODES.lock().unwrap();
    let values = VALUES.lock().unwrap();
    let constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let a = unsafe { (*a).0 };
    assert!(a < nodes.len());
    if !constant[a] {
        dbg!(trace(a, nodes.as_slice()));
        eprintln!("Fr_isTrue is only supported for constants");
    }
    values[a] != U256::ZERO
}

pub unsafe fn Fr_eq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Eq, to, a, b);
}

pub unsafe fn Fr_neq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Neq, to, a, b);
}

pub unsafe fn Fr_lt(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Lt, to, a, b);
}

pub unsafe fn Fr_gt(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Gt, to, a, b);
}

pub unsafe fn Fr_leq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Leq, to, a, b);
}

pub unsafe fn Fr_geq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Geq, to, a, b);
}

pub unsafe fn Fr_land(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Land, to, a, b);
}

pub unsafe fn Fr_lor(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Lor, to, a, b);
}

pub unsafe fn Fr_shl(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Shl, to, a, b);
}

pub unsafe fn Fr_shr(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Shr, to, a, b);
}

pub unsafe fn Fr_band(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Band, to, a, b);
}

pub unsafe fn Fr_bor(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Bor, to, a, b);
}

pub unsafe fn Fr_bxor(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Bxor, to, a, b);
}
