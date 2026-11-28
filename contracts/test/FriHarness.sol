// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

import "../FRI.sol";
import "./TestLayout.sol";

/// @dev Thin wrapper exposing FriVerifier internals for testing.
contract FriHarness {
  function foldDst() external pure returns (bytes32) {
    return FriVerifier.FOLD_DST;
  }

  function numRounds(
    uint256 degreeBound,
    uint256 foldRate,
    uint256 maxRounds
  ) external pure returns (uint256) {
    return FriVerifier.numRounds(degreeBound, foldRate, maxRounds);
  }

  function foldingChallenge(bytes32 previous, bytes32 rootHash) external pure returns (uint256) {
    return FriVerifier.foldingChallenge(previous, rootHash);
  }

  function foldingChallenges(
    bytes32 transcriptHash,
    bytes32[] calldata roots
  ) external pure returns (uint256[] memory) {
    return FriVerifier.foldingChallenges(transcriptHash, roots);
  }

  function reverseBits(uint256 index, uint256 numBits) external pure returns (uint256) {
    return FriVerifier.reverseBits(index, numBits);
  }

  function validateCommitment(
    FriOptions calldata options,
    FriCommitment calldata commitment
  ) external pure returns (uint256 rounds) {
    FriVerifier.validateOptions(options);
    return FriVerifier.validateCommitment(options, commitment);
  }

  /// @dev Validates the parameters and the commitment, and verifies a single query at `index` against it, with the
  ///   folding challenges chained to `transcriptHash`. `proof` is SCPF data with
  ///   `TEST_LAYOUT_IDENTIFIER` containing the openings of the query, and nothing else.
  function verifyQuery(
    FriOptions calldata options,
    bytes32 transcriptHash,
    bytes calldata proof,
    uint256 index,
    FriCommitment calldata commitment,
    uint256 value
  ) external view {
    FriOptions memory decodedOptions = options;
    FriCommitment memory decodedCommitment = commitment;
    FriVerifier.validateOptions(decodedOptions);
    FriVerifier.validateCommitment(decodedOptions, decodedCommitment);
    uint256[] memory challenges = FriVerifier.foldingChallenges(
      transcriptHash,
      decodedCommitment.roots
    );
    ProofViewer memory viewer = ProofViewerMethods.open(proof, TEST_LAYOUT_IDENTIFIER);
    FriVerifier.verifyQuery(decodedOptions, viewer, index, decodedCommitment, challenges, value);
    ProofViewerMethods.close(viewer);
  }

  /// @dev Validates the parameters and the commitment once, derives its folding challenges once from
  ///   `transcriptHash`, and verifies all the queries against it, with `values[i]` being the
  ///   expected evaluation at `indices[i]`. `proof` is SCPF data with `TEST_LAYOUT_IDENTIFIER`
  ///   containing the openings of all the queries, one query after the other.
  function verifyQueries(
    FriOptions calldata options,
    bytes32 transcriptHash,
    bytes calldata proof,
    uint256[] calldata indices,
    FriCommitment calldata commitment,
    uint256[] calldata values
  ) external view {
    FriOptions memory decodedOptions = options;
    FriCommitment memory decodedCommitment = commitment;
    FriVerifier.validateOptions(decodedOptions);
    FriVerifier.validateCommitment(decodedOptions, decodedCommitment);
    uint256[] memory challenges = FriVerifier.foldingChallenges(
      transcriptHash,
      decodedCommitment.roots
    );
    ProofViewer memory viewer = ProofViewerMethods.open(proof, TEST_LAYOUT_IDENTIFIER);
    for (uint256 i = 0; i < indices.length; i++) {
      FriVerifier.verifyQuery(
        decodedOptions,
        viewer,
        indices[i],
        decodedCommitment,
        challenges,
        values[i]
      );
    }
    ProofViewerMethods.close(viewer);
  }
}
