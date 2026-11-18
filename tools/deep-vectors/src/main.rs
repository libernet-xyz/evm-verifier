// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Generates DEEP-FRI test vectors for the Solidity verifier using the reference Rust
//! implementation in `starkom-pcs` with the Keccak-256 hash backend over the BlueSky field.
//!
//! Every test case contains a commitment and a proof serialized with the canonical proto3 JSON
//! mapping of the `starkom-pcs` protobufs, so for example `bytes` fields are base64 strings and
//! `uint64` fields are decimal strings, plus the same proof encoded in SCPF as a 0x-prefixed hex
//! string, with the standalone layout read by `DeepVerifier.verify`.
//!
//! Usage: `cargo run --release > ../../test/vectors/deep.json`

use primitive_types::H256;
use prost::Message;
use serde::Serialize;
use starkom_bluesky::Scalar;
use starkom_ff::Field;
use starkom_pcs::hash::Keccak256Hash;
use starkom_pcs::starkom::proto::pcs::v11 as pcs_proto;
use starkom_pcs::{Commitment, Committer, MAX_FRI_ROUNDS, Options, Proof};
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

impl prost::Name for proto::Proof {
    const NAME: &'static str = "Proof";
    const PACKAGE: &'static str = "starkom.proto.pcs.v11";
}

type Hash = Keccak256Hash<Scalar>;

/// Loads a BlueSky element from a protobuf, which stores it as the little-endian bytes of its
/// canonical integer value.
fn load_scalar(bytes: &[u8]) -> Scalar {
    Scalar::try_from_le_bytes(bytes).unwrap()
}

/// Pushes BlueSky elements stored in a protobuf, as inline words.
fn push_scalars(encoder: &mut Encoder, values: &[Vec<u8>]) {
    encoder.push_scalars(values.iter().map(|value| load_scalar(value)));
}

/// Pushes hashes stored in a protobuf, as pool references.
fn push_hashes(encoder: &mut Encoder, hashes: &[Vec<u8>]) {
    encoder.push_hashes(hashes.iter().map(|hash| H256::from_slice(hash)));
}

/// Transcodes a DEEP-FRI proof from protobuf to SCPF, with the standalone layout read by
/// `DeepVerifier.verify`: the parameters, the nonce, and the opened points (every X-coordinate
/// followed by its evaluations), then the FRI roots and the folded quotient, then the queries, every
/// one with the openings of all the batches followed by the folds of all the rounds.
fn encode_proof(proof: &pcs_proto::Proof) -> Vec<u8> {
    let mut encoder = Encoder::default();
    encoder.push_u64(proof.degree_bound);
    encoder.push_u64(proof.security_bits.into());
    encoder.push_u64(proof.blowup_log2.into());
    encoder.push_u64(proof.fold_rate.into());
    encoder.push_u64(proof.max_rounds.into());
    encoder.push_u64(proof.grinding_bits.into());
    encoder.push_u64(proof.nonce);
    encoder.push_usize(proof.points.len());
    for point in &proof.points {
        encoder.push_scalar(load_scalar(&point.z));
        push_scalars(&mut encoder, &point.v);
    }
    push_hashes(&mut encoder, &proof.fri_roots);
    encoder.push_usize(proof.folded_quotient.len());
    push_scalars(&mut encoder, &proof.folded_quotient);
    for (opening, query) in proof.openings.iter().zip(&proof.queries) {
        for leaf_proof in &opening.proofs {
            push_scalars(&mut encoder, &leaf_proof.leaf_values);
            push_hashes(&mut encoder, &leaf_proof.merkle_path);
        }
        for fold in &query.folds {
            push_scalars(&mut encoder, &fold.coset_values);
            push_hashes(&mut encoder, &fold.merkle_path);
        }
    }
    encoder.finish::<proto::Proof>()
}

/// The protocol parameters used in most test cases, same as in the `starkom_pcs` unit tests.
const OPTIONS: Options = Options {
    degree_bound: 4,
    security_bits: 128,
    blowup_log2: 2,
    fold_rate: 1,
    max_rounds: MAX_FRI_ROUNDS,
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
    scpf: String,
}

/// Converts a `starkom-pcs` protobuf message to its `serde`-enabled copy through the wire format.
fn convert<M: Message, N: Message + Default>(message: &M) -> N {
    N::decode(message.encode_to_vec().as_slice()).unwrap()
}

impl TestCase {
    /// Commits to `batches`, all over the 256-bit field, and opens them at `points`.
    fn new(name: &'static str, options: Options, batches: &[&[&[u64]]], points: &[u64]) -> Self {
        Self::new_mixed(name, options, batches, &vec![false; batches.len()], points)
    }

    /// Commits to `batches` and opens them at `points`. Every batch is over the base field iff the
    /// corresponding flag in `base_fields` is set. With BlueSky the two kinds of batch only differ
    /// by the DSTs of their leaf hashes.
    fn new_mixed(
        name: &'static str,
        options: Options,
        batches: &[&[&[u64]]],
        base_fields: &[bool],
        points: &[u64],
    ) -> Self {
        assert_eq!(batches.len(), base_fields.len());
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
        let mut committer = Committer::<Scalar, Hash>::new(options);
        for (batch, &base_field) in batches.iter().zip(base_fields) {
            if base_field {
                committer.add_base_batch(make_batch(batch));
            } else {
                committer.add_batch(make_batch(batch));
            }
        }
        let (commitment, prover) = committer.commit();
        let proof = prover.prove(points.iter().copied().map(Scalar::from_const).collect());
        assert!(proof.verify(&options, &commitment).is_ok());
        let commitment_proto = commitment.to_proto();
        let proof_proto = proof.to_proto();
        // Round-trip through the protobufs to make sure `from_proto` accepts what we emit.
        let decoded_commitment = Commitment::<Scalar, Hash>::from_proto(&commitment_proto).unwrap();
        let decoded_proof = Proof::<Scalar, Hash>::from_proto(&proof_proto).unwrap();
        assert!(decoded_proof.verify(&options, &decoded_commitment).is_ok());
        let scpf = encode_proof(&proof_proto);
        Self {
            name,
            commitment: convert(&commitment_proto),
            proof: convert(&proof_proto),
            scpf: format!(
                "0x{}",
                scpf.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
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
        // Same setups as `test_base_and_extension_batches`, `test_extension_and_base_batches`, and
        // `test_three_mixed_batches` in the `starkom_pcs::deep` unit tests.
        TestCase::new_mixed(
            "base and extension batches",
            OPTIONS,
            &SAMPLE_BATCHES,
            &[true, false],
            &SAMPLE_POINTS,
        ),
        TestCase::new_mixed(
            "extension and base batches",
            OPTIONS,
            &SAMPLE_BATCHES,
            &[false, true],
            &SAMPLE_POINTS,
        ),
        TestCase::new_mixed(
            "three mixed batches",
            Options {
                grinding_bits: 8,
                ..OPTIONS
            },
            &[
                &[&[12, 34, 56, 78], &[42, 43]],
                &[&[90, 78, 56, 34]],
                &[&[1, 2, 3, 4], &[5, 6, 7, 8], &[9]],
            ],
            &[true, false, true],
            &[123, 456, 789],
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
