// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./BlueSky.sol";
import "./Keccak256Hash.sol";

/// @notice A Merkle proof for one leaf of a Merkle tree.
/// @dev Matches `starkom_pcs::merkle::Proof` and the `LeafProof` protobuf.
struct LeafProof {
    /// @dev The opened leaf values, one for every committed polynomial, in [0, P).
    uint256[] leaf;
    /// @dev The sibling hashes along the leaf-to-root path, excluding the root.
    bytes32[] path;
}

/// @title Merkle
/// @notice Verification of the Merkle trees used by Starkom, with the Keccak-256 hash backend.
/// @dev Matches `starkom_pcs::merkle`.
library Merkle {
    /// @dev Reverted when a leaf value is not a canonical field element.
    error NonCanonicalScalar(uint256 value);

    /// @dev Reverted when the leaf index does not fit in the height of the Merkle path.
    error InvalidIndex();

    /// @dev Reverted when the root hash recomputed from a proof differs from the expected one.
    error RootHashMismatch(bytes32 got, bytes32 want);

    /// @dev Domain separator for leaf hashes: `SHA3-512("starkom/merkle/leaf") mod P`.
    uint256 constant LEAF_DST =
        0x08cb2652a56289bd316cfcb356f5d2be485538e04a601fb14fc2c98f03077fcb;

    /// @notice Checks that all leaf values of a proof are canonical field elements.
    /// @dev Performs the checks of `Proof::from_proto`, which rejects out-of-range scalars. Hashes
    ///   can't be out of range with the Keccak-256 backend.
    function validate(LeafProof memory proof) internal pure {
        uint256[] memory leaf = proof.leaf;
        for (uint256 i = 0; i < leaf.length; i++) {
            if (leaf[i] >= BlueSky.P) {
                revert NonCanonicalScalar(leaf[i]);
            }
        }
    }

    /// @notice Hashes a leaf of a Merkle tree.
    /// @dev Hashes `LEAF_DST`, then the number of values, then the values. Matches `hash_leaf`.
    function hashLeaf(uint256[] memory values) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(LEAF_DST, values.length, values));
    }

    /// @notice Verifies a Merkle proof against a root hash, reverting if it's invalid.
    /// @dev Matches `Proof::verify`.
    /// @param proof The leaf values and sibling hashes.
    /// @param index The leaf index, which determines the left/right position at each level.
    /// @param rootHash The expected Merkle root.
    function verify(
        LeafProof memory proof,
        uint256 index,
        bytes32 rootHash
    ) internal pure {
        bytes32 hash = hashLeaf(proof.leaf);
        bytes32[] memory path = proof.path;
        for (uint256 i = 0; i < path.length; i++) {
            if (index & 1 != 0) {
                hash = Keccak256Hash.hashBinary(path[i], hash);
            } else {
                hash = Keccak256Hash.hashBinary(hash, path[i]);
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

    /// @notice Returns true iff all the committed polynomials are constant.
    /// @dev A proof witnesses constant polynomials when every sibling hash equals the running hash,
    ///   which happens when all leaves of the tree are identical. Matches `Proof::is_constant`.
    function isConstant(LeafProof memory proof) internal pure returns (bool) {
        bytes32 hash = hashLeaf(proof.leaf);
        bytes32[] memory path = proof.path;
        for (uint256 i = 0; i < path.length; i++) {
            if (path[i] != hash) {
                return false;
            }
            hash = Keccak256Hash.hashBinary(hash, hash);
        }
        return true;
    }
}
