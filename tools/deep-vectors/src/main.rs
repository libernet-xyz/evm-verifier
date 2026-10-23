// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates DEEP-FRI test vectors for the Solidity verifier using the reference Rust
//! implementation in `starkom-pcs` with the Keccak-256 hash backend over the BlueSky field.
//!
//! Every test case contains a commitment and a proof serialized with the canonical proto3 JSON
//! mapping of the `starkom-pcs` protobufs, so for example `bytes` fields are base64 strings and
//! `uint64` fields are decimal strings.
//!
//! Usage: `cargo run --release > ../../test/vectors/deep.json`

use prost::Message;
use serde::Serialize;
use starkom_bluesky::Scalar;
use starkom_pcs::hash::Keccak256Hash;
use starkom_pcs::{Commitment, Committer, Options, Proof};
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

/// The protocol parameters used in most test cases, same as in the `starkom_pcs` unit tests.
const OPTIONS: Options = Options {
    degree_bound: 4,
    blowup_log2: 2,
    fold_rate: 1,
    max_rounds: usize::MAX,
    grinding_bits: 0,
};

/// Two batches of polynomials of degree 3, the first with two polynomials and the second with one,
/// same as in the `starkom_pcs` unit tests.
const SAMPLE_BATCHES: [&[&[u64]]; 2] = [
    &[&[12, 34, 56, 78], &[42, 43, 44, 45]],
    &[&[90, 78, 56, 34]],
];

/// The points opened in most test cases.
const SAMPLE_POINTS: [u64; 2] = [123, 456];

/// A DEEP-FRI test case: a commitment and a proof opening it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TestCase {
    name: &'static str,
    commitment: proto::Commitment,
    proof: proto::Proof,
}

/// Converts a `starkom-pcs` protobuf message to its `serde`-enabled copy through the wire format.
fn convert<M: Message, N: Message + Default>(message: &M) -> N {
    N::decode(message.encode_to_vec().as_slice()).unwrap()
}

impl TestCase {
    fn new(name: &'static str, options: Options, batches: &[&[&[u64]]], points: &[u64]) -> Self {
        let make_batch = |batch: &[&[u64]]| -> Vec<Polynomial<Scalar>> {
            batch
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
                .collect()
        };
        let mut committer = Committer::<Scalar, Hash>::new(options, make_batch(batches[0]));
        for batch in &batches[1..] {
            committer.add_batch(make_batch(batch));
        }
        let (commitment, prover) = committer.commit();
        let proof = prover.prove(points.iter().copied().map(Scalar::from_const).collect());
        assert!(proof.verify(&commitment).is_ok());
        let commitment_proto = commitment.to_proto();
        let proof_proto = proof.to_proto();
        // Round-trip through the protobufs to make sure `from_proto` accepts what we emit.
        let decoded_commitment = Commitment::<Scalar, Hash>::from_proto(&commitment_proto).unwrap();
        let decoded_proof = Proof::<Scalar, Hash>::from_proto(&proof_proto).unwrap();
        assert!(decoded_proof.verify(&decoded_commitment).is_ok());
        Self {
            name,
            commitment: convert(&commitment_proto),
            proof: convert(&proof_proto),
        }
    }
}

fn main() {
    let cases = [
        // Same setup as `sample_proof(OPTIONS)` in the `starkom_pcs::deep` unit tests.
        TestCase::new("sample", OPTIONS, &SAMPLE_BATCHES, &SAMPLE_POINTS),
        TestCase::new(
            "sample with grinding",
            Options {
                grinding_bits: 8,
                ..OPTIONS
            },
            &SAMPLE_BATCHES,
            &SAMPLE_POINTS,
        ),
        // Same setup as `test_reject_foreign_commitment` in the `starkom_pcs::deep` unit tests.
        TestCase::new(
            "foreign",
            OPTIONS,
            &[
                &[&[99, 98, 97, 96], &[95, 94, 93, 92]],
                &[&[91, 90, 89, 88]],
            ],
            &SAMPLE_POINTS,
        ),
        TestCase::new(
            "constant polynomial",
            Options {
                degree_bound: 1,
                ..OPTIONS
            },
            &[&[&[12]]],
            &[123],
        ),
        TestCase::new(
            "one polynomial at one point",
            OPTIONS,
            &[&[&[12, 34, 56, 78]]],
            &[123],
        ),
        TestCase::new("three points", OPTIONS, &SAMPLE_BATCHES, &[789, 456, 123]),
        TestCase::new(
            "three batches",
            OPTIONS,
            &[
                &[&[12, 34], &[56]],
                &[&[78, 90, 12, 34]],
                &[&[42, 43, 44, 45], &[1, 2], &[3]],
            ],
            &SAMPLE_POINTS,
        ),
        TestCase::new(
            "blowup 8",
            Options {
                blowup_log2: 3,
                ..OPTIONS
            },
            &SAMPLE_BATCHES,
            &SAMPLE_POINTS,
        ),
        TestCase::new(
            "fold rate 2",
            Options {
                degree_bound: 8,
                fold_rate: 2,
                ..OPTIONS
            },
            &[&[&[12, 34, 56, 78, 90, 12, 34, 56]]],
            &SAMPLE_POINTS,
        ),
        TestCase::new(
            "fold rate 3 with grinding",
            Options {
                degree_bound: 16,
                fold_rate: 3,
                grinding_bits: 8,
                ..OPTIONS
            },
            &[
                &[&[12, 34, 56, 78, 90, 12, 34, 56], &[42, 43]],
                &[&[1, 2, 3, 4]],
            ],
            &SAMPLE_POINTS,
        ),
        TestCase::new(
            "one round",
            Options {
                degree_bound: 8,
                max_rounds: 1,
                ..OPTIONS
            },
            &[&[&[12, 34, 56, 78, 90, 12, 34, 56]]],
            &SAMPLE_POINTS,
        ),
        TestCase::new(
            "zero rounds",
            Options {
                max_rounds: 0,
                ..OPTIONS
            },
            &SAMPLE_BATCHES,
            &SAMPLE_POINTS,
        ),
    ];
    println!("{}", serde_json::to_string(&cases).unwrap());
}
