// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

import "../Merkle.sol";
import "./TestLayout.sol";

/// @dev Thin wrapper exposing Merkle internals for testing. The Merkle paths are passed as SCPF
///   data with `TEST_LAYOUT_IDENTIFIER`, whose stream contains only the pool references of the
///   sibling hashes.
contract MerkleHarness {
  function leafDst() external pure returns (uint256) {
    return Merkle.LEAF_DST;
  }

  function baseLeafDst() external pure returns (uint256) {
    return Merkle.BASE_LEAF_DST;
  }

  function hashLeaf(uint256[] calldata values) external pure returns (bytes32) {
    uint256 offset;
    assembly {
      offset := values.offset
    }
    return Merkle.hashLeaf(offset, values.length);
  }

  function hashBaseLeaf(uint256[] calldata values) external pure returns (bytes32) {
    uint256 offset;
    assembly {
      offset := values.offset
    }
    return Merkle.hashBaseLeaf(offset, values.length);
  }

  function verifyPath(
    bytes32 leaf,
    bytes calldata path,
    uint256 height,
    uint256 index,
    bytes32 rootHash
  ) external pure {
    ProofViewer memory viewer = ProofViewerMethods.open(path, TEST_LAYOUT_IDENTIFIER);
    Merkle.verifyPath(leaf, viewer, height, index, rootHash);
    ProofViewerMethods.close(viewer);
  }
}
