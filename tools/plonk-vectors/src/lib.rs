// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Shared code of the PLONK test vector generators of the Solidity verifier.
//!
//! A test case consists of two files: `<name>.scpf`, a PLONK proof encoded in SCPF by
//! `Proof::to_scpf`, and `<name>.circuit.json`, what the verifier knows about the circuit (see
//! `PlonkCircuit` in `PLONK.sol`). Every proof is checked with the Rust verifier before being
//! written.
//!
//! The circuit of a test case can also get the Solidity verifier generated for it by
//! `CompressedCircuit::make_solidity_verifier` (see `write_verifier`).

use serde::Serialize;
use starkom_bluesky::Scalar;
use starkom_pcs::hash::Keccak256Hash;
use starkom_plonk::solidity::Options;
use starkom_plonk::starkom::proto::plonk::v12 as proto;
use starkom_plonk::{Circuit, CompressedCircuit, Proof};
use std::collections::BTreeSet;
use std::path::Path;

/// The hash backend of the proofs, the only one supported by the Solidity verifier.
pub type Hash = Keccak256Hash<Scalar>;

/// The settings of the PCS that the circuit fixes, in the format of `DeepOptions` (see `DEEP.sol`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PcsConfig {
    degree_bound: usize,
    security_bits: usize,
    blowup_log2: usize,
    grinding_bits: usize,
}

#[derive(Serialize)]
struct PublicCell {
    row: usize,
    column: usize,
}

/// What the Solidity verifier knows about a circuit (see `PlonkCircuit` in `PLONK.sol`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CircuitDescription {
    /// The Merkle root of the circuit batch, as a 0x-prefixed hex string.
    commitment: String,
    pcs_config: PcsConfig,
    num_rows: usize,
    num_columns: usize,
    num_gate_selectors: usize,
    num_quotient_chunks: usize,
    blinded: bool,
    /// The rotations of the variables of the gate constraints, plus 0 and 1, in increasing order.
    rotations: Vec<i64>,
    /// The public cells, in increasing order.
    public_cells: Vec<PublicCell>,
}

/// Describes `circuit` for the Solidity verifier, deriving the batch sizes and the rotations like
/// `CompressedCircuit::verify` does, and checks the description against an honest `proof`.
fn describe(
    circuit: &CompressedCircuit<Scalar, Scalar, Hash>,
    proof: &Proof<Scalar, Scalar, Hash>,
) -> CircuitDescription {
    let compressed: proto::CompressedCircuit = circuit.to_proto();
    let num_gate_selectors = compressed
        .gates
        .iter()
        .flat_map(|gate| {
            gate.instances
                .iter()
                .map(|instance| instance.selector_index)
        })
        .collect::<BTreeSet<u64>>()
        .len();
    let rotations: BTreeSet<i64> = compressed
        .gates
        .iter()
        .flat_map(|gate| gate.constraint.iter())
        .flat_map(|constraint| constraint.monomials.iter())
        .flat_map(|monomial| monomial.powers.iter())
        .filter_map(|power| power.variable.as_ref().map(|variable| variable.rotation))
        .chain([0, 1])
        .collect();

    // The quotient is split into chunks of degree bound N minus that of the masks of a blinded
    // circuit, which compensate for the rotations and the largest number of queries.
    let pcs_config = circuit.pcs_config();
    let degree_bound = pcs_config.degree_bound;
    let quotient_degree_bound =
        (degree_bound - 1) * std::cmp::max(circuit.get_max_gate_degree(), 3);
    let mask_degree_bound = if circuit.is_blinded() {
        let num_queries = starkom_pcs::num_queries(
            pcs_config.security_bits,
            pcs_config.blowup_log2,
            pcs_config.grinding_bits,
        );
        rotations.len() + num_queries + 1
    } else {
        0
    };
    let num_quotient_chunks = quotient_degree_bound.div_ceil(degree_bound - mask_degree_bound);

    // An honest proof must have batches of the derived sizes.
    let batches = proof.to_proto().commitment.unwrap().batches;
    let blinded = usize::from(circuit.is_blinded());
    assert_eq!(batches.len(), 4);
    assert_eq!(
        batches[0].num_polys as usize,
        num_gate_selectors + circuit.num_columns() + 1
    );
    assert_eq!(batches[1].num_polys as usize, circuit.num_columns());
    assert_eq!(batches[2].num_polys as usize, circuit.num_columns() + 1);
    assert_eq!(batches[3].num_polys as usize, num_quotient_chunks + blinded);

    CircuitDescription {
        commitment: format!("{:?}", circuit.commitment()),
        pcs_config: PcsConfig {
            degree_bound,
            security_bits: pcs_config.security_bits,
            blowup_log2: pcs_config.blowup_log2,
            grinding_bits: pcs_config.grinding_bits,
        },
        num_rows: circuit.num_rows(),
        num_columns: circuit.num_columns(),
        num_gate_selectors,
        num_quotient_chunks,
        blinded: circuit.is_blinded(),
        rotations: rotations.into_iter().collect(),
        public_cells: circuit
            .public_cells()
            .iter()
            .map(|cell| PublicCell {
                row: cell.row(),
                column: cell.column(),
            })
            .collect(),
    }
}

/// Verifies `proof` against `circuit` with the Rust verifier, then writes the test case
/// `<directory>/<name>.scpf` and `<directory>/<name>.circuit.json`.
pub fn write_case(
    directory: &Path,
    name: &str,
    circuit: &Circuit<Scalar, Scalar>,
    proof: &Proof<Scalar, Scalar, Hash>,
) {
    let circuit = circuit.as_compressed::<Hash>();
    circuit.verify(proof).unwrap();
    write_circuit(directory, name, &circuit, proof);
    write_proof(directory, name, proof);
}

/// Writes `<directory>/<name>.circuit.json`, checking the description against an honest `proof`.
pub fn write_circuit(
    directory: &Path,
    name: &str,
    circuit: &CompressedCircuit<Scalar, Scalar, Hash>,
    proof: &Proof<Scalar, Scalar, Hash>,
) {
    let description = serde_json::to_string_pretty(&describe(circuit, proof)).unwrap();
    std::fs::write(
        directory.join(format!("{name}.circuit.json")),
        description + "\n",
    )
    .unwrap();
}

/// Writes `<directory>/<name>.scpf`, the proof encoded by `Proof::to_scpf`.
pub fn write_proof(directory: &Path, name: &str, proof: &Proof<Scalar, Scalar, Hash>) {
    std::fs::write(directory.join(format!("{name}.scpf")), proof.to_scpf()).unwrap();
}

/// Writes the libraries of the Solidity verifier of `circuit` generated by
/// `CompressedCircuit::make_solidity_verifier`, whose names start with `verifier_name`, to
/// `directory`, each in `<library name>.sol`.
///
/// `circuit` must be that of the test case `<vectors_directory>/<name>`, so that the verifier
/// verifies its proof: their commitments are checked to be the same.
pub fn write_verifier(
    vectors_directory: &Path,
    name: &str,
    circuit: &Circuit<Scalar, Scalar>,
    directory: &Path,
    verifier_name: &str,
) {
    let circuit = circuit.as_compressed::<Hash>();
    let description_path = vectors_directory.join(format!("{name}.circuit.json"));
    let description: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(description_path).unwrap()).unwrap();
    assert_eq!(
        description["commitment"].as_str().unwrap(),
        format!("{:?}", circuit.commitment()),
        "the circuit isn't the one of the test case {name}"
    );
    let libraries = circuit
        .make_solidity_verifier(
            verifier_name,
            &Options {
                spdx_license_identifier: "Apache-2.0".to_string(),
                ..Options::default()
            },
        )
        .unwrap();
    for library in libraries {
        std::fs::write(
            directory.join(format!("{}.sol", library.name)),
            library.source,
        )
        .unwrap();
    }
}
