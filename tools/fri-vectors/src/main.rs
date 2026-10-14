// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates FRI test vectors for the Solidity verifier using the reference Rust implementation in
//! `starkom-pcs` with the Keccak-256 hash backend over the BlueSky field.
//!
//! Usage: `cargo run --release > ../../test/vectors/fri.json`

use starkom_bluesky::Scalar;
use starkom_pcs::fri::{Prover, Query};
use starkom_pcs::hash::Keccak256Hash;
use starkom_poly::Polynomial;

type Hash = Keccak256Hash<Scalar>;

/// Converts a little-endian scalar encoding (as stored in protobufs) to a big-endian hex string.
fn scalar_hex(little_endian: &[u8]) -> String {
    let mut bytes = [0u8; 32];
    bytes[0..little_endian.len()].copy_from_slice(little_endian);
    bytes.reverse();
    format!("\"0x{}\"", hex(&bytes))
}

fn hash_hex(bytes: &[u8]) -> String {
    format!("\"0x{}\"", hex(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn leaf_proof_json(proof: &starkom_pcs::starkom::proto::pcs::v8::LeafProof) -> String {
    let leaf: Vec<String> = proof
        .leaf_values
        .iter()
        .map(|value| scalar_hex(value))
        .collect();
    let path: Vec<String> = proof
        .merkle_path
        .iter()
        .map(|hash| hash_hex(hash))
        .collect();
    format!(
        "{{\"leaf\":[{}],\"path\":[{}]}}",
        leaf.join(","),
        path.join(",")
    )
}

fn case_json(
    name: &str,
    coefficients: &[Vec<u64>],
    degree_bound: usize,
    blowup_log2: usize,
) -> String {
    let polynomials: Vec<Polynomial<Scalar>> = coefficients
        .iter()
        .map(|coefficients| {
            Polynomial::with_coefficients(
                coefficients
                    .iter()
                    .copied()
                    .map(Scalar::from_const)
                    .collect(),
            )
        })
        .collect();
    let prover = Prover::<Scalar, Hash>::new(polynomials, degree_bound, blowup_log2);
    let commitment = prover.commit();
    let roots: Vec<String> = commitment
        .roots()
        .iter()
        .map(|root| hash_hex(root.as_bytes()))
        .collect();
    let n = degree_bound << blowup_log2;
    let mut queries = Vec::with_capacity(n);
    for index in 0..n {
        let query = prover.query(index);
        assert!(query.verify(&commitment).is_ok());
        let proto = query.to_proto();
        // Round-trip through the protobuf to make sure `from_proto` accepts what we emit.
        let decoded = Query::<Scalar, Hash>::from_proto(degree_bound, blowup_log2, &proto).unwrap();
        assert!(decoded.verify(&commitment).is_ok());
        let folds: Vec<String> = proto
            .folds
            .iter()
            .map(|fold| {
                format!(
                    "{{\"left\":{},\"right\":{}}}",
                    leaf_proof_json(fold.left.as_ref().unwrap()),
                    leaf_proof_json(fold.right.as_ref().unwrap())
                )
            })
            .collect();
        queries.push(format!(
            "{{\"index\":{},\"folds\":[{}]}}",
            proto.index,
            folds.join(",")
        ));
    }
    format!(
        "{{\"name\":\"{name}\",\"degreeBound\":{degree_bound},\"blowupLog2\":{blowup_log2},\
         \"roots\":[{}],\"queries\":[{}]}}",
        roots.join(","),
        queries.join(",")
    )
}

fn main() {
    let cases = [
        case_json("one constant polynomial", &[vec![12]], 1, 1),
        case_json(
            "three constant polynomials",
            &[vec![34], vec![56], vec![78]],
            1,
            2,
        ),
        case_json("one polynomial of degree 1", &[vec![12, 34]], 2, 1),
        case_json(
            "two polynomials of degree 1",
            &[vec![12, 34], vec![56, 78]],
            2,
            3,
        ),
        case_json(
            "three polynomials of degree 3",
            &[
                vec![42, 43, 44, 45],
                vec![12, 34, 56, 78],
                vec![34, 56, 78, 90],
            ],
            4,
            2,
        ),
        // Same setup as the "honest prover" in the `starkom_pcs::fri` unit tests.
        case_json(
            "one polynomial of degree 7",
            &[vec![12, 34, 56, 78, 90, 12, 34, 56]],
            8,
            2,
        ),
        // Same setup as the "foreign commitment" in the `starkom_pcs::fri` unit tests.
        case_json(
            "foreign polynomial of degree 7",
            &[vec![90, 78, 56, 34, 12, 90, 78, 56]],
            8,
            2,
        ),
        case_json(
            "two polynomials of degree 15",
            &[
                (1..=16).collect(),
                (1..=16).map(|value| value * 1_000_003 + 7).collect(),
            ],
            16,
            1,
        ),
        // Polynomials whose degree is lower than the degree bound still fold to constants.
        case_json(
            "low-degree polynomial with a large bound",
            &[vec![5, 6]],
            8,
            1,
        ),
    ];
    println!("[{}]", cases.join(","));
}
