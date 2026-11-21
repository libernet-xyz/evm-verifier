// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "@starkom/bluesky-sol/contracts/BlueSky.sol";

/// @title Keccak256Hash
/// @notice The Keccak-256 hash backend of Starkom over the BlueSky field.
/// @dev Mirrors `starkom_pcs::hash::Keccak256Hash` over BlueSky.
library Keccak256Hash {
  /// @dev 2^256 mod P, used to reduce a 512-bit hash to a field element.
  uint256 constant RANGE_MOD_P = 0x00000000000000000000000000000003f318441ac2c955707ffffffffffffffe;

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
  /// @dev Hashes the DST, then the transcript length as a 32-byte big-endian integer, then the
  ///   transcript elements. Matches `Hasher::hash_transcript`.
  ///
  ///   The length word followed by the elements is exactly the memory layout of `transcript`, so
  ///   rather than copying the transcript this function temporarily overwrites the word that
  ///   precedes it with `dst`, hashes in place, and restores the original word. That word belongs
  ///   to some other memory object (or is the free memory pointer, if `transcript` is the empty
  ///   array at the zero slot), so the assembly block is not memory-safe, but no other code runs
  ///   between the write and the restore.
  function hashTranscript(
    bytes32 dst,
    bytes32[] memory transcript
  ) internal pure returns (bytes32 result) {
    assembly {
      let start := sub(transcript, 0x20)
      let saved := mload(start)
      mstore(start, dst)
      result := keccak256(start, add(shl(5, mload(transcript)), 0x40))
      mstore(start, saved)
    }
  }

  /// @notice Generates a Fiat-Shamir challenge from a transcript.
  /// @dev Hashes the transcript with `dst`, then hashes that hash with `dst + 1` (as a
  ///   single-element transcript), and reduces the 512-bit concatenation of the two hashes (the
  ///   first one being the most significant half) modulo P. Matches `Hasher::challenge`.
  function challenge(bytes32 dst, bytes32[] memory transcript) internal pure returns (uint256) {
    bytes32 high = hashTranscript(dst, transcript);
    bytes32 low = _hashSingleElementTranscript(bytes32(uint256(dst) + 1), high);
    return addmod(mulmod(uint256(high), RANGE_MOD_P, BlueSky.P), uint256(low), BlueSky.P);
  }

  /// @dev Same as `hashTranscript` with a transcript made of `element` alone, but without
  ///   allocating the transcript.
  function _hashSingleElementTranscript(
    bytes32 dst,
    bytes32 element
  ) private pure returns (bytes32 result) {
    assembly ("memory-safe") {
      // The input is assembled in the unallocated memory past the free memory pointer.
      let input := mload(0x40)
      mstore(input, dst)
      mstore(add(input, 0x20), 1)
      mstore(add(input, 0x40), element)
      result := keccak256(input, 0x60)
    }
  }
}
