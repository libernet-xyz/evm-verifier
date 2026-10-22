// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../FRI.sol";

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

    function foldingChallenge(
        bytes32 rootHash
    ) external pure returns (uint256) {
        return FriVerifier.foldingChallenge(rootHash);
    }

    function reverseBits(
        uint256 index,
        uint256 numBits
    ) external pure returns (uint256) {
        return FriVerifier.reverseBits(index, numBits);
    }

    /// @dev Validates the commitment and verifies a single query against it.
    function verifyQuery(
        FriOptions calldata options,
        FriQuery calldata query,
        FriCommitment calldata commitment,
        uint256 value
    ) external view {
        FriVerifier.validateCommitment(commitment);
        FriVerifier.verifyQuery(options, query, commitment, value);
    }

    /// @dev Validates the commitment once and verifies all the queries against it, with
    ///   `values[i]` being the expected evaluation of `queries[i]`. The options and the commitment
    ///   are copied to memory only once.
    function verifyQueries(
        FriOptions calldata options,
        FriQuery[] calldata queries,
        FriCommitment calldata commitment,
        uint256[] calldata values
    ) external view {
        FriOptions memory decodedOptions = options;
        FriCommitment memory decodedCommitment = commitment;
        FriVerifier.validateCommitment(decodedCommitment);
        for (uint256 i = 0; i < queries.length; i++) {
            FriVerifier.verifyQuery(decodedOptions, queries[i], decodedCommitment, values[i]);
        }
    }
}
