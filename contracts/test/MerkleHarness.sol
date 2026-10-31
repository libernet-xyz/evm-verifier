// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../Merkle.sol";

/// @dev Thin wrapper exposing Merkle internals for testing. The Merkle paths are passed as proofs
///   in the calldata format whose heap contains only the pool indices of the sibling hashes.
contract MerkleHarness {
    function leafDst() external pure returns (uint256) {
        return Merkle.LEAF_DST;
    }

    function hashLeaf(uint256[] calldata values) external pure returns (bytes32) {
        uint256 offset;
        assembly {
            offset := values.offset
        }
        return Merkle.hashLeaf(offset, values.length);
    }

    function verify(
        uint256[] calldata leaf,
        bytes calldata path,
        uint256 height,
        uint256 index,
        bytes32 rootHash
    ) external pure {
        uint256 offset;
        assembly {
            offset := leaf.offset
        }
        ProofViewer memory viewer = ProofViewerMethods.open(path);
        Merkle.verify(offset, leaf.length, viewer, height, index, rootHash);
        ProofViewerMethods.close(viewer);
    }

    function verifyPath(
        bytes32 leaf,
        bytes calldata path,
        uint256 height,
        uint256 index,
        bytes32 rootHash
    ) external pure {
        ProofViewer memory viewer = ProofViewerMethods.open(path);
        Merkle.verifyPath(leaf, viewer, height, index, rootHash);
        ProofViewerMethods.close(viewer);
    }
}
