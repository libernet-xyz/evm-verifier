// Copyright 2026 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

//! Encodes `starkom-pcs` DEEP-FRI proofs in the compact calldata format read by the Solidity
//! verifier (see `ProofViewer` in `contracts/ProofViewer.sol`).
//!
//! A proof is encoded as `varint(pool size) || pool || heap`:
//!
//! - the **pool** holds every distinct hash of the proof (the FRI roots and the sibling hashes of
//!   all the Merkle paths) as 32-byte words, sorted by decreasing number of references and then by
//!   first reference, so that the most referenced hashes get the shortest indices;
//! - the **heap** holds everything else in proof order: small integers as varints, field elements
//!   as inline 32-byte big-endian words, and hashes as the varint indices of their pool words.
//!
//! The heap contains, in order:
//!
//! 1. the protocol parameters and the other integers of the proof: `degree_bound`,
//!    `security_bits`, `blowup_log2`, `fold_rate`, `max_rounds`, `grinding_bits`, `nonce`, and
//!    `num_polys`;
//! 2. the number of opened points, then for every point its X-coordinate followed by its
//!    `num_polys` evaluations;
//! 3. the FRI roots, then the number of coefficients of the folded quotient followed by the
//!    coefficients;
//! 4. for every query, the openings of all the batches (for every batch, the leaf values followed
//!    by the Merkle path from the leaf up), then the folds of all the FRI rounds (for every round,
//!    the coset values followed by the Merkle path from the root of the coset subtree up).
//!
//! The numbers that the verifier can derive are not encoded: the number of FRI rounds and queries
//! and the heights of the Merkle paths (from the protocol parameters), the number of values of
//! every leaf (from the commitment), and the query indices (from the proof of work).
//!
//! Varints are big-endian with a prefix that encodes their length: the number of leading one bits
//! of the first byte is the number of bytes that follow it, so 1 byte holds 7 bits, 2 bytes hold 14
//! bits, and so on up to 8 bytes holding 56 bits. Values of 57 bits or more take 9 bytes: `0xff`
//! followed by the 64-bit value.

use anyhow::{Result, anyhow};
use starkom_pcs::starkom::proto::pcs::v9 as proto;
use std::cmp::Reverse;
use std::collections::HashMap;

/// An element of the heap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item {
    /// A small integer, encoded as a varint.
    Varint(u64),
    /// A field element, encoded inline as a 32-byte big-endian word.
    Word([u8; 32]),
    /// A hash, encoded as the varint index of its word in the pool.
    Hash([u8; 32]),
}

/// Appends the varint encoding of `value` to `output` (see the module documentation).
pub fn encode_varint(value: u64, output: &mut Vec<u8>) {
    match (1..=8).find(|length| value >> (7 * length) == 0) {
        Some(length) => {
            let prefix = ((1u64 << (length - 1)) - 1) << (7 * length + 1);
            output.extend_from_slice(&(prefix | value).to_be_bytes()[(8 - length)..]);
        }
        None => {
            output.push(0xff);
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Converts a field element of the protobufs (canonical form, little-endian bytes) into a 32-byte
/// big-endian word.
fn scalar_word(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() > 32 {
        return Err(anyhow!("invalid scalar of {} bytes", bytes.len()));
    }
    let mut word = [0u8; 32];
    for (i, &byte) in bytes.iter().enumerate() {
        word[31 - i] = byte;
    }
    Ok(word)
}

/// Converts a hash of the protobufs into a 32-byte word.
fn hash_word(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid hash of {} bytes", bytes.len()))
}

fn push_scalars(items: &mut Vec<Item>, scalars: &[Vec<u8>]) -> Result<()> {
    for scalar in scalars {
        items.push(Item::Word(scalar_word(scalar)?));
    }
    Ok(())
}

fn push_hashes(items: &mut Vec<Item>, hashes: &[Vec<u8>]) -> Result<()> {
    for hash in hashes {
        items.push(Item::Hash(hash_word(hash)?));
    }
    Ok(())
}

/// Lists the heap elements of a proof, in heap order.
fn proof_items(proof: &proto::Proof) -> Result<Vec<Item>> {
    if proof.openings.len() != proof.queries.len() {
        return Err(anyhow!(
            "the proof has {} openings and {} queries",
            proof.openings.len(),
            proof.queries.len()
        ));
    }
    let mut items = vec![
        Item::Varint(proof.degree_bound),
        Item::Varint(proof.security_bits.into()),
        Item::Varint(proof.blowup_log2.into()),
        Item::Varint(proof.fold_rate.into()),
        Item::Varint(proof.max_rounds),
        Item::Varint(proof.grinding_bits.into()),
        Item::Varint(proof.nonce),
        Item::Varint(proof.num_polys),
        Item::Varint(proof.points.len() as u64),
    ];
    for point in &proof.points {
        items.push(Item::Word(scalar_word(&point.z)?));
        push_scalars(&mut items, &point.v)?;
    }
    push_hashes(&mut items, &proof.fri_roots)?;
    items.push(Item::Varint(proof.folded_quotient.len() as u64));
    push_scalars(&mut items, &proof.folded_quotient)?;
    for (opening, query) in proof.openings.iter().zip(&proof.queries) {
        for merkle_proof in &opening.proofs {
            push_scalars(&mut items, &merkle_proof.leaf_values)?;
            push_hashes(&mut items, &merkle_proof.merkle_path)?;
        }
        for fold in &query.folds {
            push_scalars(&mut items, &fold.coset_values)?;
            push_hashes(&mut items, &fold.merkle_path)?;
        }
    }
    Ok(items)
}

/// Builds the pool of the hashes referenced by `items` and encodes the pool and the heap.
fn encode_items(items: &[Item]) -> Vec<u8> {
    // The number of references and the position of the first reference of every hash.
    let mut references: HashMap<[u8; 32], (usize, usize)> = HashMap::new();
    for (position, item) in items.iter().enumerate() {
        if let Item::Hash(hash) = item {
            references.entry(*hash).or_insert((0, position)).0 += 1;
        }
    }
    let mut pool: Vec<[u8; 32]> = references.keys().copied().collect();
    pool.sort_by_key(|hash| {
        let (count, first) = references[hash];
        (Reverse(count), first)
    });
    let indices: HashMap<[u8; 32], u64> = pool
        .iter()
        .enumerate()
        .map(|(index, hash)| (*hash, index as u64))
        .collect();

    let mut output = vec![];
    encode_varint(pool.len() as u64, &mut output);
    for hash in &pool {
        output.extend_from_slice(hash);
    }
    for item in items {
        match item {
            Item::Varint(value) => encode_varint(*value, &mut output),
            Item::Word(word) => output.extend_from_slice(word),
            Item::Hash(hash) => encode_varint(indices[hash], &mut output),
        }
    }
    output
}

/// Encodes a DEEP-FRI proof in the calldata format of the Solidity verifier.
///
/// The proof is encoded as it is, without validating it: an error is returned only if it can't be
/// represented, that is if its number of openings differs from its number of queries, if a field
/// element has more than 32 bytes, or if a hash doesn't have exactly 32 bytes.
pub fn encode_proof(proof: &proto::Proof) -> Result<Vec<u8>> {
    Ok(encode_items(&proof_items(proof)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns the little-endian encoding of a small field element, as in the protobufs.
    fn scalar(value: u8) -> Vec<u8> {
        let mut bytes = vec![0; 32];
        bytes[0] = value;
        bytes
    }

    /// Returns the big-endian word of a small field element, as in the calldata.
    fn word(value: u8) -> [u8; 32] {
        let mut word = [0; 32];
        word[31] = value;
        word
    }

    /// Returns a hash made of 32 copies of the given byte.
    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// A proof with two queries, one batch, and one FRI round. Hash 0xbb appears in the Merkle
    /// paths of both batch openings, hash 0xdd in the Merkle paths of both folds, and the other
    /// hashes once each.
    fn sample_proof() -> proto::Proof {
        let opening = |leaf: u8, path: [u8; 2]| proto::proof::Opening {
            proofs: vec![proto::MerkleProof {
                leaf_values: vec![scalar(leaf)],
                merkle_path: path.iter().map(|&byte| hash(byte).to_vec()).collect(),
            }],
        };
        let query = |index: u64, coset: [u8; 2]| proto::Query {
            index,
            folds: vec![proto::query::LeafProof {
                coset_values: coset.iter().map(|&value| scalar(value)).collect(),
                merkle_path: vec![hash(0xdd).to_vec()],
            }],
        };
        proto::Proof {
            hash_backend: None,
            degree_bound: 4,
            security_bits: 128,
            blowup_log2: 2,
            fold_rate: 1,
            max_rounds: u64::MAX,
            grinding_bits: 8,
            nonce: 300,
            num_polys: 1,
            points: vec![proto::proof::Point {
                z: scalar(123),
                v: vec![scalar(45)],
            }],
            fri_roots: vec![hash(0x11).to_vec()],
            folded_quotient: vec![scalar(7)],
            openings: vec![opening(10, [0xaa, 0xbb]), opening(11, [0xcc, 0xbb])],
            queries: vec![query(5, [20, 21]), query(9, [22, 23])],
        }
    }

    fn test_encode_varint_impl(value: u64, expected: &[u8]) {
        let mut output = vec![];
        encode_varint(value, &mut output);
        assert_eq!(output, expected);
    }

    #[test]
    fn test_encode_varint() {
        test_encode_varint_impl(0, &[0x00]);
        test_encode_varint_impl(1, &[0x01]);
        test_encode_varint_impl(127, &[0x7f]);
        test_encode_varint_impl(128, &[0x80, 0x80]);
        test_encode_varint_impl(300, &[0x81, 0x2c]);
        test_encode_varint_impl(16383, &[0xbf, 0xff]);
        test_encode_varint_impl(16384, &[0xc0, 0x40, 0x00]);
        test_encode_varint_impl((1 << 21) - 1, &[0xdf, 0xff, 0xff]);
        test_encode_varint_impl(1 << 21, &[0xe0, 0x20, 0x00, 0x00]);
        test_encode_varint_impl((1 << 28) - 1, &[0xef, 0xff, 0xff, 0xff]);
        test_encode_varint_impl(1 << 28, &[0xf0, 0x10, 0x00, 0x00, 0x00]);
        test_encode_varint_impl(
            (1 << 56) - 1,
            &[0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        );
        test_encode_varint_impl(1 << 56, &[0xff, 0x01, 0, 0, 0, 0, 0, 0, 0]);
        test_encode_varint_impl(u64::MAX, &[0xff; 9]);
    }

    #[test]
    fn test_scalar_word() {
        let mut bytes = vec![0; 32];
        bytes[0] = 0x01;
        bytes[1] = 0x02;
        bytes[31] = 0x7f;
        let mut expected = [0; 32];
        expected[0] = 0x7f;
        expected[30] = 0x02;
        expected[31] = 0x01;
        assert_eq!(scalar_word(&bytes).unwrap(), expected);
    }

    #[test]
    fn test_short_scalar_word() {
        assert_eq!(scalar_word(&[0x34, 0x12]).unwrap(), {
            let mut expected = [0; 32];
            expected[30] = 0x12;
            expected[31] = 0x34;
            expected
        });
    }

    #[test]
    fn test_long_scalar_word() {
        assert!(scalar_word(&[0; 33]).is_err());
    }

    #[test]
    fn test_hash_word() {
        assert_eq!(hash_word(&[0x42; 32]).unwrap(), [0x42; 32]);
    }

    #[test]
    fn test_short_hash_word() {
        assert!(hash_word(&[0x42; 31]).is_err());
    }

    #[test]
    fn test_long_hash_word() {
        assert!(hash_word(&[0x42; 33]).is_err());
    }

    #[test]
    fn test_encode_proof() {
        let proof = sample_proof();
        let calldata = encode_proof(&proof).unwrap();
        // The pool has the two hashes referenced twice first, then the others in order of first
        // reference: 0xbb, 0xdd, 0x11, 0xaa, 0xcc.
        let expected = [
            &[5][..],
            &hash(0xbb)[..],
            &hash(0xdd)[..],
            &hash(0x11)[..],
            &hash(0xaa)[..],
            &hash(0xcc)[..],
            // Degree bound, security bits (128 takes two bytes), blowup, fold rate, max rounds.
            &[4, 0x80, 0x80, 2, 1][..],
            &[0xff; 9][..],
            // Grinding bits, nonce, number of polynomials, number of points.
            &[8, 0x81, 0x2c, 1, 1][..],
            &word(123)[..],
            &word(45)[..],
            // The FRI root and the number of coefficients of the folded quotient.
            &[2, 1][..],
            &word(7)[..],
            // First query: batch opening, then fold.
            &word(10)[..],
            &[3, 0][..],
            &word(20)[..],
            &word(21)[..],
            &[1][..],
            // Second query.
            &word(11)[..],
            &[4, 0][..],
            &word(22)[..],
            &word(23)[..],
            &[1][..],
        ]
        .concat();
        assert_eq!(calldata, expected);
    }

    #[test]
    fn test_encode_proof_without_queries() {
        let mut proof = sample_proof();
        proof.openings.clear();
        proof.queries.clear();
        let calldata = encode_proof(&proof).unwrap();
        let expected = [
            &[1][..],
            &hash(0x11)[..],
            &[4, 0x80, 0x80, 2, 1][..],
            &[0xff; 9][..],
            &[8, 0x81, 0x2c, 1, 1][..],
            &word(123)[..],
            &word(45)[..],
            &[0, 1][..],
            &word(7)[..],
        ]
        .concat();
        assert_eq!(calldata, expected);
    }

    #[test]
    fn test_encode_proof_with_more_openings_than_queries() {
        let mut proof = sample_proof();
        proof.queries.pop();
        assert!(encode_proof(&proof).is_err());
    }

    #[test]
    fn test_encode_proof_with_short_hash() {
        let mut proof = sample_proof();
        proof.openings[1].proofs[0].merkle_path[0].pop();
        assert!(encode_proof(&proof).is_err());
    }

    #[test]
    fn test_encode_proof_with_long_scalar() {
        let mut proof = sample_proof();
        proof.queries[0].folds[0].coset_values[1].push(0);
        assert!(encode_proof(&proof).is_err());
    }
}
