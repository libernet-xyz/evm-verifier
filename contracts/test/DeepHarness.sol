// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../DEEP.sol";

/// @dev Thin wrapper exposing DeepVerifier internals for testing.
contract DeepHarness {
  function domainSeparators() external pure returns (bytes32[5] memory) {
    return
      [
        DeepVerifier.QUERY_DST0,
        DeepVerifier.QUERY_DST1,
        DeepVerifier.RLC_DST,
        DeepVerifier.QUOTIENT_DST,
        DeepVerifier.POW_DST
      ];
  }

  function proofLayoutIdentifier() external pure returns (bytes32) {
    return DeepVerifier.PROOF_LAYOUT_IDENTIFIER;
  }

  function maxFriRounds() external pure returns (uint256) {
    return DeepVerifier.MAX_FRI_ROUNDS;
  }

  function numQueries(
    uint256 securityBits,
    uint256 blowupLog2,
    uint256 grindingBits
  ) external pure returns (uint256) {
    return DeepVerifier.numQueries(securityBits, blowupLog2, grindingBits);
  }

  function satisfies(
    DeepOptions calldata options,
    DeepOptions calldata expected
  ) external pure returns (bool) {
    return DeepVerifier.satisfies(options, expected);
  }

  function deepTranscript(
    DeepOptions calldata options,
    DeepCommitment calldata commitment,
    uint256 numPolys,
    DeepPoint[] calldata points
  ) external pure returns (bytes32[] memory) {
    return DeepVerifier.deepTranscript(options, commitment, numPolys, points);
  }

  function deepChallenges(
    DeepOptions calldata options,
    DeepCommitment calldata commitment,
    uint256 numPolys,
    DeepPoint[] calldata points
  ) external pure returns (uint256 alpha, uint256 beta) {
    return
      DeepVerifier.deepChallenges(
        DeepVerifier.deepTranscript(options, commitment, numPolys, points)
      );
  }

  function querySeed(
    DeepOptions calldata options,
    DeepCommitment calldata commitment,
    uint256 numPolys,
    DeepPoint[] calldata points,
    FriCommitment calldata friCommitment
  ) external pure returns (bytes32) {
    return
      DeepVerifier.querySeed(
        DeepVerifier.deepTranscript(options, commitment, numPolys, points),
        friCommitment
      );
  }

  function proofOfWork(bytes32 seed, uint64 nonce) external pure returns (bytes32) {
    return DeepVerifier.proofOfWork(seed, nonce);
  }

  function checkProofOfWork(bytes32 pow, uint256 grindingBits) external pure returns (bool) {
    return DeepVerifier.checkProofOfWork(pow, grindingBits);
  }

  function queryIndex(bytes32 pow, uint256 i, uint256 domainSize) external pure returns (uint256) {
    return DeepVerifier.queryIndex(pow, i, domainSize);
  }

  function verify(
    DeepOptions calldata expected,
    DeepCommitment calldata commitment,
    bytes calldata proof
  ) external view returns (DeepOptions memory options, DeepPoint[] memory points) {
    return DeepVerifier.verify(expected, commitment, proof);
  }
}
