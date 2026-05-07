// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../FRI.sol";

/// @dev Thin wrapper exposing FriVerifier internals as external functions for testing.
contract FriHarness {
    function hashRaw(
        uint256 dst,
        uint256 a,
        uint256 b
    ) external pure returns (uint256) {
        return FriVerifier.hashRaw(dst, a, b);
    }

    function hashMany(
        uint256[] calldata inputs
    ) external pure returns (uint256) {
        uint256[] memory mem = inputs;
        return FriVerifier.hashMany(mem);
    }

    function hashLeaf(
        uint256[] calldata values
    ) external pure returns (uint256) {
        uint256[] memory mem = values;
        return FriVerifier.hashLeaf(mem);
    }

    function verifyMerklePath(
        MerkleProof calldata proof,
        uint256 index,
        uint256 rootHash
    ) external pure returns (bool) {
        MerkleProof memory mem = proof;
        return FriVerifier.verifyMerklePath(mem, index, rootHash);
    }

    function isConstant(
        MerkleProof calldata proof
    ) external pure returns (bool) {
        MerkleProof memory mem = proof;
        return FriVerifier.isConstant(mem);
    }

    function verifyQuery(
        FriQuery calldata query,
        FriCommitment calldata commitment
    ) external view {
        FriQuery memory queryMem = query;
        FriCommitment memory commitmentMem = commitment;
        FriVerifier.verifyQuery(queryMem, commitmentMem);
    }
}
