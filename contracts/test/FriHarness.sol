// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../FRI.sol";

/// @dev Thin wrapper exposing FriVerifier internals for testing.
contract FriHarness {
    function foldDst() external pure returns (bytes32) {
        return FriVerifier.FOLD_DST;
    }

    function foldingChallenge(
        bytes32 rootHash
    ) external pure returns (uint256) {
        return FriVerifier.foldingChallenge(rootHash);
    }

    function verifyQuery(
        uint256 degreeBound,
        uint256 blowupLog2,
        FriQuery calldata query,
        FriCommitment calldata commitment
    ) external view {
        FriVerifier.verifyQuery(degreeBound, blowupLog2, query, commitment);
    }
}
