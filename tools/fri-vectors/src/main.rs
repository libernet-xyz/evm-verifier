// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates FRI test vectors for the Solidity verifier using the reference Rust implementation in
//! `starkom-pcs` with the Keccak-256 hash backend over the BlueSky field.
//!
//! The FRI queries are serialized with the canonical proto3 JSON mapping of the `starkom-pcs`
//! protobufs, so for example `bytes` fields are base64 strings and `uint64` fields are decimal
//! strings, while the fields of the surrounding test cases are plain JSON. The openings of all the
//! queries are also encoded in SCPF, as read by the FRI harness (see `encode_queries`).
//!
//! Usage: `cargo run --release > ../../test/vectors/fri.json`

use primitive_types::H256;
use prost::Message;
use serde::Serialize;
use starkom_bluesky::Scalar;
use starkom_ff::Field;
use starkom_pcs::MAX_FRI_ROUNDS;
use starkom_pcs::fri::{Prover, Query};
use starkom_pcs::hash::Keccak256Hash;
use starkom_pcs::starkom::proto::pcs::v11 as pcs_proto;
use starkom_poly::Polynomial;
use starkom_scpf::Encoder;

/// Copy of the `starkom-pcs` protobuf messages with `serde` support (see `build.rs`).
///
/// Only some of them are used here.
#[allow(dead_code)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/starkom.proto.pcs.v11.rs"));
    include!(concat!(env!("OUT_DIR"), "/starkom.proto.pcs.v11.serde.rs"));
}

type Hash = Keccak256Hash<Scalar>;

/// The transcript hash that the folding challenges of all test cases are chained to, same as in the
/// `starkom_pcs::fri` unit tests. In DEEP-FRI it's the encoded quotient challenge.
const TRANSCRIPT_HASH: H256 = H256([0x5e; 32]);

/// Marker for the layout identifier `keccak256("test")` of the SCPF data that the tests pass to the
/// harnesses (see `TestLayout.sol`): with an empty package, the full name is the plain name.
#[derive(Clone, PartialEq, prost::Message)]
struct TestLayout {}

impl prost::Name for TestLayout {
    const NAME: &'static str = "test";
    const PACKAGE: &'static str = "";
}

/// Encodes the openings of FRI queries in SCPF with the test layout, one query after the other, as
/// read by `FriHarness.verifyQueries`: for every fold, the values of the opened coset as inline
/// words followed by its Merkle path as pool references.
fn encode_queries(queries: &[pcs_proto::Query]) -> String {
    let mut encoder = Encoder::default();
    for query in queries {
        for fold in &query.folds {
            encoder.push_scalars(
                fold.coset_values
                    .iter()
                    .map(|value| Scalar::try_from_le_bytes(value).unwrap()),
            );
            encoder.push_hashes(fold.merkle_path.iter().map(|hash| H256::from_slice(hash)));
        }
    }
    let data = encoder.finish::<TestLayout>();
    format!(
        "0x{}",
        data.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

/// A FRI test case: a committed polynomial and the queries for every index of its extended domain.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    name: &'static str,
    degree_bound: usize,
    blowup_log2: usize,
    fold_rate: usize,
    /// The maximum number of folding rounds, at most `MAX_FRI_ROUNDS`.
    max_rounds: usize,
    /// The transcript hash that the folding challenges are chained to, as a 0x-prefixed hex string.
    transcript_hash: String,
    /// The roots of the FRI commitment, as 0x-prefixed hex strings.
    roots: Vec<String>,
    /// The coefficients of the folded polynomial, as 0x-prefixed hex strings.
    folded_polynomial: Vec<String>,
    queries: Vec<proto::Query>,
    /// The evaluations of the committed polynomial at the queried elements, as 0x-prefixed hex
    /// strings. There's one for every query.
    values: Vec<String>,
    /// The openings of all the queries encoded in SCPF (see `encode_queries`), as a 0x-prefixed hex
    /// string.
    scpf: String,
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
            TRANSCRIPT_HASH,
        );
        let commitment = prover.commit();
        let mut queries = vec![];
        let mut protos = vec![];
        let mut values = vec![];
        for index in 0..(degree_bound << blowup_log2) {
            let query = prover.query(index);
            let value = polynomial.evaluate(query.x());
            assert!(query.verify(&commitment, TRANSCRIPT_HASH, value).is_ok());
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
            assert!(decoded.verify(&commitment, TRANSCRIPT_HASH, value).is_ok());
            // Convert to the `serde`-enabled copy of the message through the wire format.
            queries.push(proto::Query::decode(proto.encode_to_vec().as_slice()).unwrap());
            protos.push(proto);
            values.push(value.to_string());
        }
        Self {
            name,
            degree_bound,
            blowup_log2,
            fold_rate,
            max_rounds,
            transcript_hash: format!("{TRANSCRIPT_HASH:?}"),
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
            scpf: encode_queries(&protos),
        }
    }
}

fn main() {
    let degree_fifteen: Vec<u64> = (1..=16).map(|value| value * 1_000_003 + 7).collect();
    let cases = [
        TestCase::new("constant polynomial", &[12], 1, 1, 1, MAX_FRI_ROUNDS),
        TestCase::new(
            "constant polynomial with a larger blowup",
            &[34],
            1,
            2,
            1,
            MAX_FRI_ROUNDS,
        ),
        TestCase::new("polynomial of degree 1", &[12, 34], 2, 1, 1, MAX_FRI_ROUNDS),
        TestCase::new(
            "polynomial of degree 1 with a larger blowup",
            &[56, 78],
            2,
            3,
            1,
            MAX_FRI_ROUNDS,
        ),
        TestCase::new(
            "polynomial of degree 3",
            &[42, 43, 44, 45],
            4,
            2,
            1,
            MAX_FRI_ROUNDS,
        ),
        // Same setup as the "honest prover" in the `starkom_pcs::fri` unit tests.
        TestCase::new(
            "polynomial of degree 7",
            &[12, 34, 56, 78, 90, 12, 34, 56],
            8,
            2,
            1,
            MAX_FRI_ROUNDS,
        ),
        // Same setup as the "foreign commitment" in the `starkom_pcs::fri` unit tests.
        TestCase::new(
            "foreign polynomial of degree 7",
            &[90, 78, 56, 34, 12, 90, 78, 56],
            8,
            2,
            1,
            MAX_FRI_ROUNDS,
        ),
        TestCase::new(
            "polynomial of degree 15",
            &degree_fifteen,
            16,
            1,
            1,
            MAX_FRI_ROUNDS,
        ),
        // Polynomials whose degree is lower than the degree bound still fold to constants.
        TestCase::new(
            "low-degree polynomial with a large bound",
            &[5, 6],
            8,
            1,
            1,
            MAX_FRI_ROUNDS,
        ),
        TestCase::new(
            "polynomial of degree 7 with fold rate 2",
            &[12, 34, 56, 78, 90, 12, 34, 56],
            8,
            2,
            2,
            MAX_FRI_ROUNDS,
        ),
        TestCase::new(
            "polynomial of degree 15 with fold rate 2",
            &degree_fifteen,
            16,
            2,
            2,
            MAX_FRI_ROUNDS,
        ),
        TestCase::new(
            "polynomial of degree 15 with fold rate 3",
            &degree_fifteen,
            16,
            2,
            3,
            MAX_FRI_ROUNDS,
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
