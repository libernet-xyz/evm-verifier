// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates FRI test vectors for the Solidity verifier using the reference Rust implementation in
//! `starkom-pcs` with the Keccak-256 hash backend over the BlueSky field.
//!
//! The FRI queries are serialized with the canonical proto3 JSON mapping of the `starkom-pcs`
//! protobufs, so for example `bytes` fields are base64 strings and `uint64` fields are decimal
//! strings, while the fields of the surrounding test cases are plain JSON.
//!
//! Usage: `cargo run --release > ../../test/vectors/fri.json`

use prost::Message;
use serde::Serialize;
use starkom_bluesky::Scalar;
use starkom_pcs::fri::{Prover, Query};
use starkom_pcs::hash::Keccak256Hash;
use starkom_poly::Polynomial;

/// Copy of the `starkom-pcs` protobuf messages with `serde` support (see `build.rs`).
///
/// Only some of them are used here.
#[allow(dead_code)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/starkom.proto.pcs.v9.rs"));
    include!(concat!(env!("OUT_DIR"), "/starkom.proto.pcs.v9.serde.rs"));
}

type Hash = Keccak256Hash<Scalar>;

/// A FRI test case: a committed polynomial and the queries for every index of its extended domain.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    name: &'static str,
    degree_bound: usize,
    blowup_log2: usize,
    fold_rate: usize,
    /// The maximum number of folding rounds, as a decimal string like the `uint64` fields of the
    /// protobufs (it can be `usize::MAX`).
    max_rounds: String,
    /// The roots of the FRI commitment, as 0x-prefixed hex strings.
    roots: Vec<String>,
    /// The coefficients of the folded polynomial, as 0x-prefixed hex strings.
    folded_polynomial: Vec<String>,
    queries: Vec<proto::Query>,
    /// The evaluations of the committed polynomial at the queried elements, as 0x-prefixed hex
    /// strings. There's one for every query.
    values: Vec<String>,
}

impl TestCase {
    fn new(
        name: &'static str,
        coefficients: &[u64],
        degree_bound: usize,
        blowup_log2: usize,
        fold_rate: usize,
        max_rounds: usize,
    ) -> Self {
        let polynomial = Polynomial::with_coefficients(
            coefficients
                .iter()
                .copied()
                .map(Scalar::from_const)
                .collect(),
        );
        let prover = Prover::<Scalar, Hash>::new(
            polynomial.clone(),
            degree_bound,
            blowup_log2,
            fold_rate,
            max_rounds,
        );
        let commitment = prover.commit();
        let mut queries = vec![];
        let mut values = vec![];
        for index in 0..(degree_bound << blowup_log2) {
            let query = prover.query(index);
            let value = polynomial.evaluate(query.x());
            assert!(query.verify(&commitment, value).is_ok());
            let proto = query.to_proto();
            // Round-trip through the protobuf to make sure `from_proto` accepts what we emit.
            let decoded = Query::<Scalar, Hash>::from_proto(
                degree_bound,
                blowup_log2,
                fold_rate,
                max_rounds,
                &proto,
            )
            .unwrap();
            assert!(decoded.verify(&commitment, value).is_ok());
            // Convert to the `serde`-enabled copy of the message through the wire format.
            queries.push(proto::Query::decode(proto.encode_to_vec().as_slice()).unwrap());
            values.push(value.to_string());
        }
        Self {
            name,
            degree_bound,
            blowup_log2,
            fold_rate,
            max_rounds: max_rounds.to_string(),
            roots: commitment
                .roots()
                .iter()
                .map(|root| format!("{root:?}"))
                .collect(),
            folded_polynomial: commitment
                .folded_polynomial()
                .coefficients()
                .iter()
                .map(Scalar::to_string)
                .collect(),
            queries,
            values,
        }
    }
}

fn main() {
    let degree_fifteen: Vec<u64> = (1..=16).map(|value| value * 1_000_003 + 7).collect();
    let cases = [
        TestCase::new("constant polynomial", &[12], 1, 1, 1, usize::MAX),
        TestCase::new(
            "constant polynomial with a larger blowup",
            &[34],
            1,
            2,
            1,
            usize::MAX,
        ),
        TestCase::new("polynomial of degree 1", &[12, 34], 2, 1, 1, usize::MAX),
        TestCase::new(
            "polynomial of degree 1 with a larger blowup",
            &[56, 78],
            2,
            3,
            1,
            usize::MAX,
        ),
        TestCase::new(
            "polynomial of degree 3",
            &[42, 43, 44, 45],
            4,
            2,
            1,
            usize::MAX,
        ),
        // Same setup as the "honest prover" in the `starkom_pcs::fri` unit tests.
        TestCase::new(
            "polynomial of degree 7",
            &[12, 34, 56, 78, 90, 12, 34, 56],
            8,
            2,
            1,
            usize::MAX,
        ),
        // Same setup as the "foreign commitment" in the `starkom_pcs::fri` unit tests.
        TestCase::new(
            "foreign polynomial of degree 7",
            &[90, 78, 56, 34, 12, 90, 78, 56],
            8,
            2,
            1,
            usize::MAX,
        ),
        TestCase::new(
            "polynomial of degree 15",
            &degree_fifteen,
            16,
            1,
            1,
            usize::MAX,
        ),
        // Polynomials whose degree is lower than the degree bound still fold to constants.
        TestCase::new(
            "low-degree polynomial with a large bound",
            &[5, 6],
            8,
            1,
            1,
            usize::MAX,
        ),
        TestCase::new(
            "polynomial of degree 7 with fold rate 2",
            &[12, 34, 56, 78, 90, 12, 34, 56],
            8,
            2,
            2,
            usize::MAX,
        ),
        TestCase::new(
            "polynomial of degree 15 with fold rate 2",
            &degree_fifteen,
            16,
            2,
            2,
            usize::MAX,
        ),
        TestCase::new(
            "polynomial of degree 15 with fold rate 3",
            &degree_fifteen,
            16,
            2,
            3,
            usize::MAX,
        ),
        TestCase::new(
            "polynomial of degree 7 with one round",
            &[12, 34, 56, 78, 90, 12, 34, 56],
            8,
            2,
            1,
            1,
        ),
        TestCase::new(
            "polynomial of degree 7 without rounds",
            &[12, 34, 56, 78, 90, 12, 34, 56],
            8,
            2,
            1,
            0,
        ),
        // The folded polynomial has 4 coefficients, of which only the first is non-zero.
        TestCase::new("low-degree polynomial with one round", &[5, 6], 8, 1, 1, 1),
    ];
    println!("{}", serde_json::to_string(&cases).unwrap());
}
