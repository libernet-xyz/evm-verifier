// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../DEEP.sol";

/// @dev Thin wrapper exposing DeepVerifier internals for testing.
contract DeepHarness {
    function domainSeparators() external pure returns (bytes32[5] memory) {
        return [
            DeepVerifier.QUERY_DST0,
            DeepVerifier.QUERY_DST1,
            DeepVerifier.RLC_DST,
            DeepVerifier.QUOTIENT_DST,
            DeepVerifier.POW_DST
        ];
    }

    function numQueries(
        uint256 blowupLog2,
        uint256 grindingBits
    ) external pure returns (uint256) {
        return DeepVerifier.numQueries(blowupLog2, grindingBits);
    }

    function deepTranscript(
        DeepCommitment calldata commitment,
        uint256 numPolys,
        DeepPoint[] calldata points
    ) external pure returns (bytes32[] memory) {
        return DeepVerifier.deepTranscript(commitment, numPolys, points);
    }

    function deepChallenges(
        DeepCommitment calldata commitment,
        uint256 numPolys,
        DeepPoint[] calldata points
    ) external pure returns (uint256 alpha, uint256 beta) {
        return DeepVerifier.deepChallenges(
            DeepVerifier.deepTranscript(commitment, numPolys, points)
        );
    }

    function querySeed(
        DeepCommitment calldata commitment,
        uint256 numPolys,
        DeepPoint[] calldata points,
        FriCommitment calldata friCommitment
    ) external pure returns (bytes32) {
        return DeepVerifier.querySeed(
            DeepVerifier.deepTranscript(commitment, numPolys, points),
            friCommitment
        );
    }

    function proofOfWork(bytes32 seed, uint64 nonce) external pure returns (bytes32) {
        return DeepVerifier.proofOfWork(seed, nonce);
    }

    function checkProofOfWork(
        bytes32 pow,
        uint256 grindingBits
    ) external pure returns (bool) {
        return DeepVerifier.checkProofOfWork(pow, grindingBits);
    }

    function queryIndex(
        bytes32 pow,
        uint256 i,
        uint256 domainSize
    ) external pure returns (uint256) {
        return DeepVerifier.queryIndex(pow, i, domainSize);
    }

    function verify(
        DeepCommitment calldata commitment,
        DeepProof calldata proof
    ) external view {
        DeepVerifier.verify(commitment, proof);
    }
}
