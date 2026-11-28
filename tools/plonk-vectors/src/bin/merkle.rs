// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates the Merkle lookup benchmarks of the Solidity verifier: PLONK proofs of lookups in
//! Sparse Merkle Trees, proven with the Keccak-256 hash backend over the BlueSky field.
//!
//! The benchmarks are listed in `BENCHMARKS`:
//!
//! - `binary-256-t4x7`: a binary tree with 256-bit keys (`FullBinaryChip`), hashed with Poseidon1
//!   T4X7;
//! - `binary-160-t4x7`: a binary tree with 160-bit keys like Ethereum addresses (`BinaryChip`),
//!   hashed with Poseidon1 T4X7;
//! - `ternary-162-t5x7`: a ternary tree with 162-trit keys (`FullTernaryChip`), hashed with
//!   Poseidon1 T5X7;
//! - `ternary-101-t5x7`: a ternary tree with 101-trit keys, enough for 160 bits (`TernaryChip`),
//!   hashed with Poseidon1 T5X7.
//!
//! The circuits are built like in the large blowup tests of the `merkle` module of
//! `starkom-gadgets`, e.g. `test_full_ternary_smt_with_large_blowup`: they're blinded and have a
//! blowup factor of 256, but they only require 16 grinding bits, i.e. ceil((128 - 16) / 8) = 14 FRI
//! queries. The proofs provide 24 grinding bits, so they only have ceil((128 - 24) / 8) = 13
//! queries, like those of a prover that found a better proof of work than the circuit requires.
//! Every inner node is the `hash0` of its children with the two DSTs of the chips (`DSTS`, both
//! zero) as capacity. All the trees hold the same five entries and the proofs look up the same key.
//!
//! Usage:
//!
//! - `cargo run --release --bin merkle -- ../../test/vectors/merkle [<benchmark>...]` writes the
//!   test case of every benchmark, or of the given ones, named after it (see
//!   `plonk_vectors::write_case`), proven with its FRI settings;
//! - `cargo run --release --bin merkle -- sweep <benchmark> <directory>` writes one test case for
//!   every useful combination of fold rate and number of rounds of a benchmark, to compare them
//!   with `scripts/tune-merkle-fri.ts`;
//! - `cargo run --release --bin merkle -- verifiers ../../test/vectors/merkle
//!   ../../contracts/test/generated` replaces the contents of the last directory with the Solidity
//!   verifier of every benchmark (see `plonk_vectors::write_verifier`), which verifies the proof of
//!   its test case. It proves nothing.
//!
//! The circuits are blinded with random values, so every run generates different proofs.

use plonk_vectors::{Hash, write_case, write_circuit, write_proof, write_verifier};
use primitive_types::U256;
use starkom_bluesky::{Scalar, from_const};
use starkom_ff::Field;
use starkom_gadgets::merkle::{BinaryChip, FullBinaryChip, FullTernaryChip, TernaryChip};
use starkom_plonk::{
    Cell, CellOrUnconstrained, Chip, Circuit, CircuitBuilder, CircuitOptions, CircuitView, Proof,
    ProofOptions, Witness, WitnessView,
};
use starkom_poseidon::{BlueSkyConfigT4X7, BlueSkyConfigT5X7};
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// A Merkle lookup benchmark.
struct Benchmark {
    name: &'static str,
    /// The prefix of the names of the libraries of its Solidity verifier.
    verifier_name: &'static str,
    /// The number of FRI folds per round of the proof.
    fold_rate: usize,
    /// The maximum number of FRI rounds of the proof, 0 to send the whole DEEP quotient in the
    /// clear.
    max_rounds: usize,
    /// Builds the circuit and the witness of the lookup.
    make_lookup: fn() -> Lookup,
}

/// The benchmarks, with the FRI settings of the smallest proof, measured with
/// `scripts/tune-merkle-fri.ts`.
///
/// On Ethereum the calldata floor determines the cost of all the settings, both today (EIP-7623)
/// and after Amsterdam (EIP-7976), so the smallest proof is also the cheapest transaction:
///
/// | benchmark          | FRI settings         | proof     | next smallest                   |
/// | ------------------ | -------------------- | --------- | ------------------------------- |
/// | `binary-256-t4x7`  | fold rate 3, 1 round | 179,020 B | fold rate 2, 1 round: +694 B    |
/// | `binary-160-t4x7`  | no rounds            | 172,847 B | fold rate 2, 1 round: +883 B    |
/// | `ternary-162-t5x7` | no rounds            | 192,827 B | fold rate 2, 1 round: +1,378 B  |
/// | `ternary-101-t5x7` | no rounds            | 184,528 B | fold rate 2, 1 round: +3,052 B  |
///
/// The sizes of the same settings vary by about half a kilobyte between runs because the query
/// indices are random, but the rankings above are robust: two sweeps agreed on those of the other
/// benchmarks, and the expected sizes of a model of the proof format agree on all of them. The
/// sweeps ran before the chips of `starkom-gadgets` reconstructed the keys with Horner's method,
/// which removed most gate selectors and an opened point, and before `ternary-101-t5x7` replaced a
/// benchmark with 102-trit keys, but the differences between the FRI settings only depend on the
/// degree bound and on the number of queries, which didn't change.
const BENCHMARKS: [Benchmark; 4] = [
    Benchmark {
        name: "binary-256-t4x7",
        verifier_name: "Binary256T4X7",
        fold_rate: 3,
        max_rounds: 1,
        make_lookup: binary_256_t4x7,
    },
    Benchmark {
        name: "binary-160-t4x7",
        verifier_name: "Binary160T4X7",
        fold_rate: 1,
        max_rounds: 0,
        make_lookup: binary_160_t4x7,
    },
    Benchmark {
        name: "ternary-162-t5x7",
        verifier_name: "Ternary162T5X7",
        fold_rate: 1,
        max_rounds: 0,
        make_lookup: ternary_162_t5x7,
    },
    Benchmark {
        name: "ternary-101-t5x7",
        verifier_name: "Ternary101T5X7",
        fold_rate: 1,
        max_rounds: 0,
        make_lookup: ternary_101_t5x7,
    },
];

/// The minimum number of grinding bits of the circuits.
const CIRCUIT_GRINDING_BITS: usize = 16;

/// The number of grinding bits of the proofs, more than the circuits require, so that the proofs
/// have fewer queries than the circuits allow.
const PROOF_GRINDING_BITS: usize = 24;

/// The entries of all the trees, as (key, value) pairs.
const ENTRIES: [(u64, u64); 5] = [(12, 34), (34, 56), (56, 78), (78, 90), (90, 12)];

/// The key looked up in all the trees.
const KEY: u64 = 56;

/// The DSTs of the chips, which initialize the capacity of every permutation. They're zero, which
/// gives the same circuits as before the chips took DSTs, so the vectors generated back then are
/// still valid.
const DSTS: [Scalar; 2] = [Scalar::ZERO; 2];

/// Hashes the children of an inner node.
type HashChildren = fn(&[Scalar]) -> Scalar;

/// Hashes the children of a node of a binary tree like the chips with Poseidon1 T4X7: `hash0` with
/// `DSTS` as capacity.
fn hash_binary_t4x7(children: &[Scalar]) -> Scalar {
    starkom_poseidon::hash0::<BlueSkyConfigT4X7, Scalar, 4, 2, 2>(DSTS, children.iter().copied())
}

/// Hashes the children of a node of a ternary tree like the chips with Poseidon1 T5X7: `hash0`
/// with `DSTS` as capacity.
fn hash_ternary_t5x7(children: &[Scalar]) -> Scalar {
    starkom_poseidon::hash0::<BlueSkyConfigT5X7, Scalar, 5, 3, 2>(DSTS, children.iter().copied())
}

/// A node of a Sparse Merkle Tree.
enum Node {
    Leaf(Scalar),
    Inner {
        hash: Scalar,
        children: Vec<Rc<Node>>,
    },
}

impl Node {
    fn hash(&self) -> Scalar {
        match self {
            Node::Leaf(value) => *value,
            Node::Inner { hash, .. } => *hash,
        }
    }
}

fn make_inner(hash_children: HashChildren, children: Vec<Rc<Node>>) -> Rc<Node> {
    let hashes: Vec<Scalar> = children.iter().map(|child| child.hash()).collect();
    Rc::new(Node::Inner {
        hash: hash_children(&hashes),
        children,
    })
}

/// A persistent Sparse Merkle Tree, like those of the tests of the `merkle` module of
/// `starkom-gadgets`.
///
/// The leaves are at level 0 and the root is at level `height`. The inner nodes at level `l` pick
/// the child of a key by its digit `l - 1` in base `arity`, so the digits are consumed from the
/// least significant one, at the bottom of the tree.
struct Tree {
    arity: usize,
    height: usize,
    hash_children: HashChildren,
    root: Rc<Node>,
}

impl Tree {
    /// Returns a tree whose leaves are all zero.
    fn new(arity: usize, height: usize, hash_children: HashChildren) -> Self {
        let mut node = Rc::new(Node::Leaf(Scalar::ZERO));
        for _ in 0..height {
            node = make_inner(hash_children, vec![node; arity]);
        }
        Self {
            arity,
            height,
            hash_children,
            root: node,
        }
    }

    /// Returns the `height` digits of `key` in base `arity`, from the least significant one.
    fn digits(&self, key: u64) -> Vec<usize> {
        let mut key = U256::from(key);
        let mut digits = Vec::with_capacity(self.height);
        for _ in 0..self.height {
            digits.push((key % self.arity).as_usize());
            key /= self.arity;
        }
        digits
    }

    fn put(&mut self, key: u64, value: Scalar) {
        let digits = self.digits(key);
        self.root = self.put_impl(&self.root, &digits, value);
    }

    /// Returns `node` with the leaf at `digits` replaced by `value`. The last digit picks the
    /// child of `node`.
    fn put_impl(&self, node: &Rc<Node>, digits: &[usize], value: Scalar) -> Rc<Node> {
        match node.as_ref() {
            Node::Leaf(_) => Rc::new(Node::Leaf(value)),
            Node::Inner { children, .. } => {
                let (&digit, rest) = digits.split_last().unwrap();
                let mut children = children.clone();
                children[digit] = self.put_impl(&children[digit], rest, value);
                make_inner(self.hash_children, children)
            }
        }
    }

    /// Returns the value of `key` and its Merkle path from the leaf up, as taken by the chips: the
    /// hashes of all the children of every inner node of the path.
    fn lookup(&self, key: u64) -> (Scalar, Vec<Vec<Scalar>>) {
        let digits = self.digits(key);
        let mut node = &self.root;
        let mut path = Vec::with_capacity(self.height);
        for &digit in digits.iter().rev() {
            let Node::Inner { children, .. } = node.as_ref() else {
                panic!("the path is longer than the tree");
            };
            path.push(children.iter().map(|child| child.hash()).collect());
            node = &children[digit];
        }
        path.reverse();
        (node.hash(), path)
    }
}

/// Builds a tree holding `ENTRIES` and looks up `KEY` in it, returning the value, the Merkle path
/// of `KEY`, and the root hash.
fn look_up(
    arity: usize,
    height: usize,
    hash_children: HashChildren,
) -> (Scalar, Vec<Vec<Scalar>>, Scalar) {
    let mut tree = Tree::new(arity, height, hash_children);
    for (key, value) in ENTRIES {
        tree.put(key, from_const(value));
    }
    let (value, path) = tree.lookup(KEY);
    (value, path, tree.root.hash())
}

/// Converts a Merkle path returned by `Tree::lookup` to the array taken by the chips.
fn to_path<const N: usize, const H: usize>(path: Vec<Vec<Scalar>>) -> [[Scalar; N]; H] {
    path.into_iter()
        .map(|children| children.try_into().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// The circuit of a lookup with a valid witness.
struct Lookup {
    circuit: Circuit<Scalar, Scalar>,
    witness: Witness<Scalar>,
    root_hash_cell: Cell,
    expected_root_hash: Scalar,
}

impl Lookup {
    /// Builds the circuit of a lookup with `chip`, which declares the root hash public, and its
    /// witness for `KEY` and its `value`.
    fn new(chip: &impl Chip<Scalar, 2, 1>, value: Scalar, expected_root_hash: Scalar) -> Self {
        let mut builder = CircuitBuilder::default();
        let inputs = [builder.cell(0, 0).into(), builder.cell(0, 1).into()];
        let [root_hash] = builder.sub_chip(1, 0, chip, inputs).unwrap();
        builder.declare_public_cells([root_hash.unwrap()]);
        let circuit = builder
            .build(CircuitOptions {
                canonicalize_constraints: false,
                security_bits: 128,
                blowup_log2: 8,
                grinding_bits: CIRCUIT_GRINDING_BITS,
                blind: true,
            })
            .unwrap();

        let mut witness = circuit.make_witness();
        let inputs = [witness.cell(0, 0), witness.cell(0, 1)];
        witness.set(inputs[0], from_const(KEY));
        witness.set(inputs[1], value);
        let [root_hash] = witness
            .sub_chip(1, 0, chip, inputs.map(CellOrUnconstrained::Cell))
            .unwrap();
        let root_hash_cell = match root_hash {
            CellOrUnconstrained::Cell(cell) => cell,
            _ => panic!(),
        };
        circuit.check_witness(&witness).unwrap();
        Self {
            circuit,
            witness,
            root_hash_cell,
            expected_root_hash,
        }
    }
}

fn binary_256_t4x7() -> Lookup {
    let (value, path, root_hash) = look_up(2, 256, hash_binary_t4x7);
    let chip = FullBinaryChip::<Scalar, BlueSkyConfigT4X7>::new(DSTS, to_path(path));
    Lookup::new(&chip, value, root_hash)
}

fn binary_160_t4x7() -> Lookup {
    let (value, path, root_hash) = look_up(2, 160, hash_binary_t4x7);
    let chip = BinaryChip::<Scalar, 160, BlueSkyConfigT4X7>::new(DSTS, to_path(path));
    Lookup::new(&chip, value, root_hash)
}

fn ternary_162_t5x7() -> Lookup {
    let (value, path, root_hash) = look_up(3, 162, hash_ternary_t5x7);
    let chip = FullTernaryChip::<Scalar, BlueSkyConfigT5X7>::new(DSTS, to_path(path));
    Lookup::new(&chip, value, root_hash)
}

fn ternary_101_t5x7() -> Lookup {
    let (value, path, root_hash) = look_up(3, 101, hash_ternary_t5x7);
    let chip = TernaryChip::<Scalar, 101, BlueSkyConfigT5X7>::new(DSTS, to_path(path));
    Lookup::new(&chip, value, root_hash)
}

/// Proves the lookup with the given FRI settings, checking the root hash with the Rust verifier.
fn prove(lookup: &Lookup, fold_rate: usize, max_rounds: usize) -> Proof<Scalar, Scalar, Hash> {
    let options = ProofOptions {
        fri_fold_rate: fold_rate,
        max_fri_rounds: max_rounds,
        grinding_bits: PROOF_GRINDING_BITS,
    };
    let proof = lookup
        .circuit
        .prove::<Hash>(lookup.witness.clone(), &options)
        .unwrap();
    let openings = lookup.circuit.verify(&proof).unwrap();
    assert_eq!(openings[&lookup.root_hash_cell], lookup.expected_root_hash);
    proof
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, name, directory] if command == "sweep" => {
            let benchmark = BENCHMARKS
                .iter()
                .find(|benchmark| benchmark.name == name)
                .unwrap_or_else(|| panic!("unknown benchmark {name}"));
            let lookup = (benchmark.make_lookup)();
            // Every number of rounds from 1 to the largest one for every fold rate, plus no rounds
            // at all, where the fold rate doesn't matter.
            let directory = PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            let degree_bound = lookup.circuit.pcs_config().degree_bound;
            let degree_bound_log2 = degree_bound.trailing_zeros() as usize;
            let mut settings = vec![("no-rounds".to_string(), 1, 0)];
            for fold_rate in 1..=degree_bound_log2 {
                for rounds in 1..=(degree_bound_log2 / fold_rate) {
                    let name = format!("fold-rate-{fold_rate}-{rounds}-rounds");
                    settings.push((name, fold_rate, rounds));
                }
            }
            let circuit = lookup.circuit.as_compressed::<Hash>();
            for (name, fold_rate, rounds) in settings {
                eprintln!("proving {name}");
                let proof = prove(&lookup, fold_rate, rounds);
                write_circuit(&directory, &name, &circuit, &proof);
                write_proof(&directory, &name, &proof);
            }
        }
        [command, vectors_directory, directory] if command == "verifiers" => {
            let directory = PathBuf::from(directory);
            if directory.exists() {
                std::fs::remove_dir_all(&directory).unwrap();
            }
            std::fs::create_dir_all(&directory).unwrap();
            for benchmark in &BENCHMARKS {
                eprintln!("generating the verifier of {}", benchmark.name);
                let lookup = (benchmark.make_lookup)();
                write_verifier(
                    Path::new(vectors_directory),
                    benchmark.name,
                    &lookup.circuit,
                    &directory,
                    benchmark.verifier_name,
                );
            }
        }
        [directory, names @ ..] => {
            for name in names {
                if !BENCHMARKS.iter().any(|benchmark| benchmark.name == name) {
                    panic!("unknown benchmark {name}");
                }
            }
            let directory = PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            // All the benchmarks if none is given.
            let benchmarks = BENCHMARKS.iter().filter(|benchmark| {
                names.is_empty() || names.iter().any(|name| name == benchmark.name)
            });
            for benchmark in benchmarks {
                eprintln!("proving {}", benchmark.name);
                let lookup = (benchmark.make_lookup)();
                let proof = prove(&lookup, benchmark.fold_rate, benchmark.max_rounds);
                write_case(&directory, benchmark.name, &lookup.circuit, &proof);
            }
        }
        _ => panic!(
            "usage: merkle <directory> [<benchmark>...] | merkle sweep <benchmark> <directory> | \
             merkle verifiers <vectors directory> <directory>"
        ),
    }
}
