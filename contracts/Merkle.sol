// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./Keccak256Hash.sol";
import "./ProofViewer.sol";

/// @title Merkle
/// @notice Verification of the Merkle trees used by Starkom, with the Keccak-256 hash backend.
/// @dev Matches `starkom_pcs::merkle`. Leaf values and Merkle paths are read from a proof encoded
///   in SCPF (see `ProofViewer`): the leaf values of the trees of the committed polynomial batches
///   are inline words of the stream, and the sibling hashes are pool references.
library Merkle {
  using ProofViewerMethods for ProofViewer;

  /// @dev Reverted when a leaf value is not a canonical field element.
  error NonCanonicalScalar(uint256 value);

  /// @dev Reverted when the leaf index does not fit in the height of the Merkle path.
  error InvalidIndex();

  /// @dev Reverted when the root hash recomputed from a proof differs from the expected one.
  error RootHashMismatch(bytes32 got, bytes32 want);

  /// @dev Domain separator for the leaf hashes of polynomials over the extension field:
  ///   `SHA3-512("starkom/merkle/leaf") mod P`.
  uint256 constant LEAF_DST = 0x08cb2652a56289bd316cfcb356f5d2be485538e04a601fb14fc2c98f03077fcb;

  /// @dev Domain separator for the leaf hashes of polynomials over the base field:
  ///   `SHA3-512("starkom/merkle/leaf/base") mod P`.
  uint256 constant BASE_LEAF_DST =
    0x2e704cc1e66fb23985c37d2b9530ed50c0e48ae8fa82f63fd25fe7f78bb23a89;

  /// @dev Hashes `dst`, then `count`, then the `count` 32-byte words at calldata offset
  ///   `offset`.
  function _hashLeaf(
    uint256 dst,
    uint256 offset,
    uint256 count
  ) private pure returns (bytes32 hash) {
    assembly ("memory-safe") {
      // The input is assembled in the unallocated memory past the free memory pointer.
      let input := mload(0x40)
      mstore(input, dst)
      mstore(add(input, 0x20), count)
      calldatacopy(add(input, 0x40), offset, shl(5, count))
      hash := keccak256(input, add(shl(5, count), 0x40))
    }
  }

  /// @notice Hashes a leaf of a Merkle tree of polynomials over the extension field, whose
  ///   values are the `count` 32-byte words at calldata offset `offset`.
  /// @dev Hashes `LEAF_DST`, then the number of values, then the values. Matches
  ///   `WideLeafHasher::hash`: BlueSky is a prime field, so every evaluation is a single value.
  function hashLeaf(uint256 offset, uint256 count) internal pure returns (bytes32) {
    return _hashLeaf(LEAF_DST, offset, count);
  }

  /// @notice Hashes a leaf of a Merkle tree of polynomials over the base field, whose values are
  ///   the `count` 32-byte words at calldata offset `offset`.
  /// @dev Same as `hashLeaf` with `BASE_LEAF_DST` rather than `LEAF_DST`. Matches
  ///   `BaseLeafHasher::hash`.
  function hashBaseLeaf(uint256 offset, uint256 count) internal pure returns (bytes32) {
    return _hashLeaf(BASE_LEAF_DST, offset, count);
  }

  /// @notice Verifies the Merkle proof of a leaf of a tree of polynomials over the extension
  ///   field, reverting if it's invalid.
  /// @dev Matches `Proof::verify`. The leaf values are the `count` words at calldata offset
  ///   `offset`, and the `height` sibling hashes of the Merkle path are read from `viewer`.
  /// @param index The leaf index, which determines the left/right position at each level.
  /// @param rootHash The expected Merkle root.
  function verify(
    uint256 offset,
    uint256 count,
    ProofViewer memory viewer,
    uint256 height,
    uint256 index,
    bytes32 rootHash
  ) internal pure {
    verifyPath(hashLeaf(offset, count), viewer, height, index, rootHash);
  }

  /// @notice Recomputes a Merkle root from a leaf and its Merkle path, and checks it against
  ///   `rootHash`, reverting if they differ.
  /// @dev Matches `merkle::verify_path`. `leaf` is the hash of the leaf values for vector leaves,
  ///   or the leaf itself for trees whose leaves are single 32-byte values, like the FRI ones.
  ///   The `height` sibling hashes of the path, from the leaf up to but excluding the root, are
  ///   read from `viewer`.
  /// @param index The leaf index, which determines the left/right position at each level.
  /// @param rootHash The expected Merkle root.
  function verifyPath(
    bytes32 leaf,
    ProofViewer memory viewer,
    uint256 height,
    uint256 index,
    bytes32 rootHash
  ) internal pure {
    bytes32 hash = leaf;
    for (uint256 i = 0; i < height; i++) {
      bytes32 sibling = viewer.popPoolWord();
      if (index & 1 != 0) {
        hash = Keccak256Hash.hashBinary(sibling, hash);
      } else {
        hash = Keccak256Hash.hashBinary(hash, sibling);
      }
      index >>= 1;
    }
    if (index != 0) {
      revert InvalidIndex();
    }
    if (hash != rootHash) {
      revert RootHashMismatch(hash, rootHash);
    }
  }
}
