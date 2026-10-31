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

    function foldingChallenge(bytes32 rootHash) external pure returns (uint256) {
        return FriVerifier.foldingChallenge(rootHash);
    }

    function reverseBits(uint256 index, uint256 numBits) external pure returns (uint256) {
        return FriVerifier.reverseBits(index, numBits);
    }

    function validateCommitment(
        FriOptions calldata options,
        FriCommitment calldata commitment
    ) external pure returns (uint256 rounds) {
        return FriVerifier.validateCommitment(options, commitment);
    }

    /// @dev Validates the commitment and verifies a single query at `index` against it. `proof`
    ///   contains the openings of the query in the calldata format, and nothing else.
    function verifyQuery(
        FriOptions calldata options,
        bytes calldata proof,
        uint256 index,
        FriCommitment calldata commitment,
        uint256 value
    ) external view {
        FriOptions memory decodedOptions = options;
        FriCommitment memory decodedCommitment = commitment;
        FriVerifier.validateCommitment(decodedOptions, decodedCommitment);
        ProofViewer memory viewer = ProofViewerMethods.open(proof);
        FriVerifier.verifyQuery(decodedOptions, viewer, index, decodedCommitment, value);
        ProofViewerMethods.close(viewer);
    }

    /// @dev Validates the commitment once and verifies all the queries against it, with
    ///   `values[i]` being the expected evaluation at `indices[i]`. `proof` contains the openings
    ///   of all the queries in the calldata format, one query after the other.
    function verifyQueries(
        FriOptions calldata options,
        bytes calldata proof,
        uint256[] calldata indices,
        FriCommitment calldata commitment,
        uint256[] calldata values
    ) external view {
        FriOptions memory decodedOptions = options;
        FriCommitment memory decodedCommitment = commitment;
        FriVerifier.validateCommitment(decodedOptions, decodedCommitment);
        ProofViewer memory viewer = ProofViewerMethods.open(proof);
        for (uint256 i = 0; i < indices.length; i++) {
            FriVerifier.verifyQuery(
                decodedOptions,
                viewer,
                indices[i],
                decodedCommitment,
                values[i]
            );
        }
        ProofViewerMethods.close(viewer);
    }
}
