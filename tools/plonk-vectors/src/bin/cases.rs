// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates the PLONK test vectors of the unit tests of the Solidity verifier: proofs of Vitalik's
//! circuit, which proves knowledge of x such that x^3 + x + 5 = 35 like in the unit tests of
//! `starkom-plonk`, with several circuit and proof settings.
//!
//! Usage: `cargo run --release --bin cases -- ../../test/vectors/plonk`, then format the circuit
//! descriptions with `npx prettier --write test/vectors/plonk` from the root of the repository.
//!
//! Blinded circuits are blinded with random values, so their proofs change at every run.

use plonk_vectors::{Hash, write_case};
use starkom_bluesky::Scalar;
use starkom_plonk::{
    Cell, Circuit, CircuitBuilder, CircuitOptions, CircuitView, Constraint, ProofOptions, Witness,
    WitnessView, var,
};
use std::path::PathBuf;
use std::time::Instant;

fn cell(row: usize, column: usize) -> Cell {
    Cell::new(row, column)
}

/// Builds Vitalik's circuit, the same as `build_generic_vitalik_circuit` in the unit tests of
/// `starkom-plonk`, with the cells (2, 0) and (2, 1) public.
fn build_circuit(options: CircuitOptions) -> Circuit<Scalar, Scalar> {
    let mut builder = CircuitBuilder::<Scalar, Scalar>::default();
    builder.add_gate(0, (var(0) ^ 2) - var(1));
    builder.connect(cell(0, 0).into(), cell(1, 0).into());
    builder.connect(cell(0, 1).into(), cell(1, 1).into());
    builder.add_gate(1, var(0) * var(1) + var(0) + 5 - var(2));
    builder.connect(cell(0, 0).into(), cell(2, 0).into());
    builder.connect(cell(1, 2).into(), cell(2, 1).into());
    builder.add_gate(2, Constraint::nop());
    builder.declare_public_cells([cell(2, 0), cell(2, 1)]);
    builder.build(options).unwrap()
}

/// Returns a valid witness of Vitalik's circuit: x = 3.
fn make_witness(circuit: &Circuit<Scalar, Scalar>) -> Witness<Scalar> {
    let mut witness = circuit.make_witness();
    witness.set(cell(0, 0), 3u8.into());
    witness.set(cell(0, 1), 9u8.into());
    witness.set(cell(1, 0), 3u8.into());
    witness.set(cell(1, 1), 9u8.into());
    witness.set(cell(1, 2), 35u8.into());
    witness.set(cell(2, 0), 3u8.into());
    witness.set(cell(2, 1), 35u8.into());
    witness
}

/// The settings of the circuit of a test case.
fn circuit_options(blowup_log2: usize, grinding_bits: usize, blind: bool) -> CircuitOptions {
    CircuitOptions {
        canonicalize_constraints: false,
        security_bits: 128,
        blowup_log2,
        grinding_bits,
        blind,
    }
}

/// The proof settings of a test case: the fold rate, the maximum number of rounds, and the grinding
/// bits.
type ProofSettings = (usize, usize, usize);

fn main() {
    let directory = PathBuf::from(std::env::args().nth(1).expect("missing output directory"));
    std::fs::create_dir_all(&directory).unwrap();
    // The name, the circuit settings, and the proof settings, with `None` for the defaults of the
    // circuit.
    let cases: [(&str, CircuitOptions, Option<ProofSettings>); 10] = [
        ("unblinded", circuit_options(4, 0, false), None),
        ("grinding", circuit_options(4, 8, false), None),
        (
            "more grinding than the circuit",
            circuit_options(4, 0, false),
            Some((1, starkom_pcs::MAX_FRI_ROUNDS, 12)),
        ),
        ("blowup 2", circuit_options(1, 0, false), None),
        ("blowup 8", circuit_options(3, 0, false), None),
        ("blinded", circuit_options(4, 0, true), None),
        (
            "blinded with fold rate 2",
            circuit_options(4, 0, true),
            Some((2, starkom_pcs::MAX_FRI_ROUNDS, 0)),
        ),
        (
            "blinded with fold rate 3 and one round",
            circuit_options(4, 0, true),
            Some((3, 1, 0)),
        ),
        (
            "blinded with one round",
            circuit_options(4, 0, true),
            Some((1, 1, 0)),
        ),
        (
            "blinded without rounds",
            circuit_options(4, 0, true),
            Some((1, 0, 0)),
        ),
    ];
    for (name, options, proof_settings) in cases {
        eprint!("proving {name}... ");
        let start = Instant::now();
        let circuit = build_circuit(options);
        let proof_options = match proof_settings {
            Some((fri_fold_rate, max_fri_rounds, grinding_bits)) => ProofOptions {
                fri_fold_rate,
                max_fri_rounds,
                grinding_bits,
            },
            None => circuit.default_proof_options(),
        };
        let proof = circuit
            .prove::<Hash>(make_witness(&circuit), &proof_options)
            .unwrap();
        write_case(&directory, &name.replace(' ', "-"), &circuit, &proof);
        eprintln!("{:.1} s", start.elapsed().as_secs_f64());
    }
}
