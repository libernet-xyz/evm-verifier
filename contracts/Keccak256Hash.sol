// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "./BlueSky.sol";

/// @title Keccak256Hash
/// @notice The Keccak-256 hash backend of Starkom over the BlueSky field.
/// @dev Mirrors `starkom_pcs::hash::Keccak256Hash` over BlueSky.
library Keccak256Hash {
    /// @dev 2^256 mod P, used to reduce a 512-bit hash to a field element.
    uint256 constant RANGE_MOD_P =
        0x00000000000000000000000000000003f318441ac2c955707ffffffffffffffe;

    /// @notice Hashes the provided field elements.
    /// @dev Each element is encoded as 32 big-endian bytes. This is a raw hash: no DST or element
    ///   count is prepended. Matches `Hasher::hash`.
    function hash(uint256[] memory inputs) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(inputs));
    }

    /// @notice Hashes a binary Merkle tree node. Matches `MerkleHasher::hash_binary`.
    function hashBinary(bytes32 left, bytes32 right) internal pure returns (bytes32 result) {
        assembly ("memory-safe") {
            mstore(0x00, left)
            mstore(0x20, right)
            result := keccak256(0x00, 0x40)
        }
    }

    /// @notice Hashes a Fiat-Shamir transcript.
    /// @dev Hashes the DST, then the transcript length as a 16-byte big-endian integer, then the
    ///   transcript elements. Matches `Hasher::hash_transcript`.
    function hashTranscript(
        bytes32 dst,
        bytes32[] memory transcript
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(dst, uint128(transcript.length), transcript));
    }

    /// @notice Generates a Fiat-Shamir challenge from a transcript.
    /// @dev Hashes the transcript twice, with `dst` and `dst + 1`, and reduces the 512-bit
    ///   concatenation of the two hashes (the first one being the most significant half) modulo P.
    ///   Matches `Hasher::challenge`.
    function challenge(bytes32 dst, bytes32[] memory transcript) internal pure returns (uint256) {
        uint256 high = uint256(hashTranscript(dst, transcript));
        uint256 low = uint256(hashTranscript(bytes32(uint256(dst) + 1), transcript));
        return addmod(mulmod(high, RANGE_MOD_P, BlueSky.P), low, BlueSky.P);
    }
}
