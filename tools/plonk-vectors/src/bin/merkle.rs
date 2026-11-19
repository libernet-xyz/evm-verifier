// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates the Merkle lookup benchmark of the Solidity verifier: a PLONK proof of a lookup in a
//! ternary Sparse Merkle Tree with 162-trit keys, proven with the Keccak-256 hash backend over the
//! BlueSky field.
//!
//! The circuit is the one of `test_full_ternary_smt_with_large_blowup` in the `merkle` module of
//! `starkom-gadgets` (a blinded `FullTernaryChip` with Poseidon T4X7 and a blowup factor of 256),
//! except that it requires 24 grinding bits, so there are ceil((128 - 24) / 8) = 13 FRI queries.
//! The tree holds the same five entries and the proof looks up the same key.
//!
//! Usage:
//!
//! - `cargo run --release --bin merkle -- ../../test/vectors` writes the test case `merkle` (see
//!   `plonk_vectors::write_case`), proven with the FRI settings in `FOLD_RATE` and `MAX_ROUNDS`;
//! - `cargo run --release --bin merkle -- sweep <directory>` writes one test case for every useful
//!   combination of fold rate and number of rounds, to compare them with
//!   `scripts/tune-merkle-fri.ts`.
//!
//! The circuit is blinded with random values, so every run generates different proofs.

use plonk_vectors::{Hash, write_case, write_circuit, write_proof};
use primitive_types::U256;
use starkom_bluesky::{Scalar, from_const};
use starkom_ff::Field;
use starkom_gadgets::merkle::FullTernaryChip;
use starkom_plonk::{
    Cell, CellOrUnconstrained, Circuit, CircuitBuilder, CircuitOptions, CircuitView, Proof,
    ProofOptions, Witness, WitnessView,
};
use starkom_poseidon::BlueSkyConfigT4X7;
use std::path::PathBuf;
use std::rc::Rc;

/// The number of FRI folds per round of the benchmark proof, chosen with
/// `scripts/tune-merkle-fri.ts`.
///
/// With 1 round of 2 folds the proof was within 0.6% of the smallest proof and of the cheapest
/// transaction, which sends the whole DEEP quotient in the clear (no rounds), but its DEEP-FRI
/// verification was 11% cheaper (5.1M gas versus 5.8M with the production profile). That's what
/// matters on chains without the calldata floor of EIP-7623, which determines the cost of these
/// proofs on Ethereum.
const FOLD_RATE: usize = 2;

/// The maximum number of FRI rounds of the benchmark proof (see `FOLD_RATE`).
const MAX_ROUNDS: usize = 1;

/// The minimum number of grinding bits of the circuit, which the proofs use too.
const GRINDING_BITS: usize = 24;

/// The height of the tree, i.e. the number of trits of its keys.
const HEIGHT: usize = 162;

/// A node of a ternary Sparse Merkle Tree hashed with Poseidon T4X7.
///
/// Copied from the tests of the `merkle` module of `starkom-gadgets`.
trait Node {
    fn hash(&self) -> Scalar;

    /// Returns the Merkle path of `key`, from the leaf up: every element holds the hashes of the
    /// three children of a node.
    fn get_merkle_path(&self, key: &U256) -> Vec<Vec<Scalar>>;

    fn put(self: Rc<Self>, key: &U256, value: Scalar) -> Rc<dyn Node>;
}

struct Leaf(Scalar);

impl Node for Leaf {
    fn hash(&self) -> Scalar {
        self.0
    }

    fn get_merkle_path(&self, _key: &U256) -> Vec<Vec<Scalar>> {
        vec![]
    }

    fn put(self: Rc<Self>, _key: &U256, value: Scalar) -> Rc<dyn Node> {
        Rc::new(Leaf(value))
    }
}

struct TernaryNode {
    level: usize,
    hash: Scalar,
    children: [Rc<dyn Node>; 3],
}

impl TernaryNode {
    fn make(level: usize, children: [Rc<dyn Node>; 3]) -> Rc<dyn Node> {
        let hash = starkom_poseidon::hash0::<BlueSkyConfigT4X7, Scalar, 4, 3, 1>(
            [Scalar::ZERO],
            [children[0].hash(), children[1].hash(), children[2].hash()],
        );
        Rc::new(TernaryNode {
            level,
            hash,
            children,
        })
    }

    fn trit_at(&self, key: &U256) -> usize {
        let divisor = U256::from(3).pow((self.level - 1).into());
        ((key / divisor) % 3).try_into().unwrap()
    }
}

impl Node for TernaryNode {
    fn hash(&self) -> Scalar {
        self.hash
    }

    fn get_merkle_path(&self, key: &U256) -> Vec<Vec<Scalar>> {
        let mut path = self.children[self.trit_at(key)].get_merkle_path(key);
        path.push(self.children.iter().map(|child| child.hash()).collect());
        path
    }

    fn put(self: Rc<Self>, key: &U256, value: Scalar) -> Rc<dyn Node> {
        let trit = self.trit_at(key);
        let mut children = self.children.clone();
        children[trit] = children[trit].clone().put(key, value);
        Self::make(self.level, children)
    }
}

/// Returns an empty tree of the given height, whose leaves are all zero.
fn get_empty_tree(height: usize) -> Rc<dyn Node> {
    let mut node: Rc<dyn Node> = Rc::new(Leaf(Scalar::ZERO));
    for level in 1..=height {
        node = TernaryNode::make(level, [node.clone(), node.clone(), node.clone()]);
    }
    node
}

/// The circuit of the lookup with a valid witness.
struct Lookup {
    circuit: Circuit<Scalar, Scalar>,
    witness: Witness<Scalar>,
    root_hash_cell: Cell,
    expected_root_hash: Scalar,
}

impl Lookup {
    /// Builds the circuit and the witness of `test_full_ternary_smt_with_large_blowup`, but with
    /// `GRINDING_BITS` grinding bits.
    fn new() -> Self {
        let mut tree = get_empty_tree(HEIGHT);
        for (key, value) in [(12, 34), (34, 56), (56, 78), (78, 90), (90, 12)] {
            tree = tree.put(&U256::from(key), from_const(value));
        }
        let key = 56u64;
        let value = from_const(78);
        let path: [[Scalar; 3]; HEIGHT] = tree
            .get_merkle_path(&U256::from(key))
            .into_iter()
            .map(|entry| entry.try_into().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let chip = FullTernaryChip::<Scalar, BlueSkyConfigT4X7>::new(path);
        let mut builder = CircuitBuilder::default();
        let inputs = [builder.cell(0, 0).into(), builder.cell(0, 1).into()];
        let [root_hash] = builder.sub_chip(1, 0, &chip, inputs).unwrap();
        builder.declare_public_cells([root_hash.unwrap()]);
        let circuit = builder
            .build(CircuitOptions {
                canonicalize_constraints: false,
                security_bits: 128,
                blowup_log2: 8,
                grinding_bits: GRINDING_BITS,
                blind: true,
            })
            .unwrap();

        let mut witness = circuit.make_witness();
        let inputs = [witness.cell(0, 0), witness.cell(0, 1)];
        witness.set(inputs[0], from_const(key));
        witness.set(inputs[1], value);
        let [root_hash] = witness
            .sub_chip(1, 0, &chip, inputs.map(CellOrUnconstrained::Cell))
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
            expected_root_hash: tree.hash(),
        }
    }
}

/// Proves the lookup with the given FRI settings.
fn prove(lookup: &Lookup, fold_rate: usize, max_rounds: usize) -> Proof<Scalar, Scalar, Hash> {
    let options = ProofOptions {
        fri_fold_rate: fold_rate,
        max_fri_rounds: max_rounds,
        grinding_bits: GRINDING_BITS,
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
    let lookup = Lookup::new();
    match arguments.as_slice() {
        [command, directory] if command == "sweep" => {
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
        [directory] => {
            let proof = prove(&lookup, FOLD_RATE, MAX_ROUNDS);
            write_case(&PathBuf::from(directory), "merkle", &lookup.circuit, &proof);
        }
        _ => panic!("usage: merkle <directory> | merkle sweep <directory>"),
    }
}
