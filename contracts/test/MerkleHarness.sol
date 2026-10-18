// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../Merkle.sol";

/// @dev Thin wrapper exposing Merkle internals for testing.
contract MerkleHarness {
    function leafDst() external pure returns (uint256) {
        return Merkle.LEAF_DST;
    }

    function validate(LeafProof calldata proof) external pure {
        Merkle.validate(proof);
    }

    function hashLeaf(
        uint256[] calldata values
    ) external pure returns (bytes32) {
        return Merkle.hashLeaf(values);
    }

    function verify(
        LeafProof calldata proof,
        uint256 index,
        bytes32 rootHash
    ) external pure {
        Merkle.verify(proof, index, rootHash);
    }

    function verifyPath(
        bytes32 leaf,
        bytes32[] calldata path,
        uint256 index,
        bytes32 rootHash
    ) external pure {
        Merkle.verifyPath(leaf, path, index, rootHash);
    }
}
