// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @notice A cursor over data encoded in SCPF, the Starkom Compact Proof Format, e.g. a DEEP-FRI
///   proof encoded by `starkom_pcs::Proof::to_scpf`.
/// @dev The data is `header || pool || stream`.
///
///   The 64-byte header holds, at these offsets:
///
///   - 0: the signature, i.e. the ASCII characters `SCPF`;
///   - 8, 9, and 10: the major, minor, and patch version numbers of the format, i.e. of the
///     `starkom-scpf` crate that encoded the data;
///   - 16: the 32-byte layout identifier, i.e. the Keccak-256 hash of the full name of the
///     encoded protobuf message, e.g. `keccak256("starkom.proto.plonk.v11.Proof")`;
///   - 48: the pool size, i.e. the number of words of the pool, as a 4-byte big-endian integer.
///
///   All the other bytes of the header are reserved and must be 0.
///
///   The pool holds 32-byte words, the hashes of the proof. The stream holds the rest of the proof
///   in order: small integers as varints, field elements as inline 32-byte big-endian words, and
///   hashes as pool references, i.e. the varint positions of their words in the pool.
///
///   Varints are big-endian with a prefix that encodes their length: the number of leading one
///   bits of the first byte is the number of bytes that follow it, so 1 byte holds 7 bits, 2 bytes
///   hold 14 bits, and so on up to 8 bytes holding 56 bits. Values of 57 bits or more take 9 bytes:
///   `0xff` followed by the 64-bit value. Like protobuf varints, non-minimal encodings are
///   accepted.
///
///   The viewer reads the calldata in place and only keeps offsets into it. Reading doesn't check
///   the end of the data: past it, the viewer reads whatever follows in the calldata, or zeros
///   past the end of the calldata. Callers must invoke `close` after reading the whole stream,
///   which reverts if the reads went past the end or stopped before it.
struct ProofViewer {
  /// @dev The calldata offset of the first word of the pool.
  uint256 pool;
  /// @dev The number of words of the pool.
  uint256 poolSize;
  /// @dev The calldata offset of the next varint or inline word to read in the stream.
  uint256 cursor;
  /// @dev The calldata offset of the end of the data.
  uint256 end;
}

/// @title ProofViewerMethods
/// @notice Decodes data encoded in SCPF (see `ProofViewer`).
library ProofViewerMethods {
  /// @dev Reverted when the header, the pool, or the stream extend past the end of the data.
  error TruncatedProof();

  /// @dev Reverted when the data doesn't start with the `SCPF` signature, or when a reserved
  ///   byte of the header isn't 0.
  error InvalidHeader();

  /// @dev Reverted when the data was encoded with an unsupported major version of SCPF.
  error UnsupportedVersion(uint256 majorVersion);

  /// @dev Reverted when the data has a different layout identifier than expected, i.e. when it
  ///   encodes a different protobuf message.
  error LayoutMismatch(bytes32 layoutIdentifier);

  /// @dev Reverted when the data continues after the end of the stream.
  error TrailingData(uint256 length);

  /// @dev Reverted when a pool reference is out of range.
  error InvalidPoolIndex(uint256 index, uint256 poolSize);

  /// @dev The size of the header in bytes.
  uint256 constant HEADER_SIZE = 64;

  /// @dev The major version number of SCPF, i.e. of the `starkom-scpf` crate, that this decoder
  ///   supports.
  ///
  ///   The minor and patch version numbers are ignored: only new layouts can use the features
  ///   added by a minor version, and new layouts have new layout identifiers.
  uint256 constant MAJOR_VERSION = 1;

  /// @dev The first 16 bytes of the header, as a 128-bit integer, without the version numbers:
  ///   the `SCPF` signature followed by zeros.
  uint256 constant HEADER_PREFIX = 0x53435046000000000000000000000000;

  /// @dev The mask of the first 16 bytes of the header that excludes the version numbers.
  uint256 constant HEADER_PREFIX_MASK = 0xffffffffffffffff000000ffffffffff;

  /// @notice Opens SCPF data, checking its header, and returns a viewer whose cursor is at the
  ///   beginning of the stream.
  /// @param layoutIdentifier The expected layout identifier.
  function open(
    bytes calldata data,
    bytes32 layoutIdentifier
  ) internal pure returns (ProofViewer memory viewer) {
    if (data.length < HEADER_SIZE) {
      revert TruncatedProof();
    }
    uint256 start;
    uint256 prefix;
    bytes32 identifier;
    uint256 suffix;
    assembly {
      start := data.offset
      // Bytes 0 to 15: the signature, the version numbers, and reserved bytes.
      prefix := shr(128, calldataload(start))
      // Bytes 16 to 47.
      identifier := calldataload(add(start, 16))
      // Bytes 32 to 63, the last 16 of which are the pool size and reserved bytes.
      suffix := calldataload(add(start, 32))
    }
    if (prefix & HEADER_PREFIX_MASK != HEADER_PREFIX || uint96(suffix) != 0) {
      revert InvalidHeader();
    }
    uint256 majorVersion = (prefix >> 56) & 0xff;
    if (majorVersion != MAJOR_VERSION) {
      revert UnsupportedVersion(majorVersion);
    }
    if (identifier != layoutIdentifier) {
      revert LayoutMismatch(identifier);
    }
    uint256 poolSize = uint32(suffix >> 96);
    // No overflow: `start` is a calldata offset and `poolSize` has at most 32 bits.
    uint256 pool;
    uint256 stream;
    unchecked {
      pool = start + HEADER_SIZE;
      stream = pool + (poolSize << 5);
    }
    uint256 end = start + data.length;
    if (stream > end) {
      revert TruncatedProof();
    }
    viewer = ProofViewer({pool: pool, poolSize: poolSize, cursor: stream, end: end});
  }

  /// @notice Returns the word at position `index` of the pool, reverting if it's out of range.
  function poolWord(ProofViewer memory self, uint256 index) internal pure returns (bytes32 word) {
    uint256 poolSize = self.poolSize;
    if (index >= poolSize) {
      revert InvalidPoolIndex(index, poolSize);
    }
    uint256 pool = self.pool;
    assembly {
      word := calldataload(add(pool, shl(5, index)))
    }
  }

  /// @notice Reads the next varint of the stream.
  function popVarint(ProofViewer memory self) internal pure returns (uint256 value) {
    uint256 next;
    (value, next) = _readVarint(self.cursor);
    self.cursor = next;
  }

  /// @notice Reads the next inline word of the stream.
  function popWord(ProofViewer memory self) internal pure returns (uint256 word) {
    uint256 cursor = self.cursor;
    assembly {
      word := calldataload(cursor)
    }
    unchecked {
      self.cursor = cursor + 32;
    }
  }

  /// @notice Reads the next pool reference of the stream and returns the referenced pool word.
  function popPoolWord(ProofViewer memory self) internal pure returns (bytes32) {
    return poolWord(self, popVarint(self));
  }

  /// @notice Skips the next `count` inline words of the stream and returns the calldata offset of
  ///   the first one, so that the caller can read them in place.
  function skipWords(
    ProofViewer memory self,
    uint256 count
  ) internal pure returns (uint256 offset) {
    offset = self.cursor;
    self.cursor = offset + count * 32;
  }

  /// @notice Reads the next `count` inline words of the stream into a new array.
  function popWords(
    ProofViewer memory self,
    uint256 count
  ) internal pure returns (uint256[] memory words) {
    uint256 offset = skipWords(self, count);
    words = new uint256[](count);
    assembly {
      calldatacopy(add(words, 0x20), offset, shl(5, count))
    }
  }

  /// @notice Checks that the stream was read exactly up to the end of the data, reverting
  ///   otherwise.
  function close(ProofViewer memory self) internal pure {
    uint256 cursor = self.cursor;
    uint256 end = self.end;
    if (cursor > end) {
      revert TruncatedProof();
    }
    if (cursor < end) {
      revert TrailingData(end - cursor);
    }
  }

  /// @dev Decodes the varint at calldata offset `offset`, returning its value and the offset of
  ///   the byte that follows it.
  function _readVarint(uint256 offset) private pure returns (uint256 value, uint256 next) {
    assembly {
      let word := calldataload(offset)
      let first := shr(248, word)
      switch lt(first, 0x80)
      case 1 {
        value := first
        next := add(offset, 1)
      }
      default {
        // The length is 1 plus the number of leading one bits of the first byte.
        let length := 2
        for {
          let mask := 0x40
        } and(first, mask) {
          mask := shr(1, mask)
        } {
          length := add(length, 1)
        }
        switch length
        case 9 {
          value := shr(192, shl(8, word))
        }
        default {
          // The top `length` bits are the prefix and the next `7 * length` bits are the
          // value.
          value := and(shr(sub(256, shl(3, length)), word), sub(shl(mul(7, length), 1), 1))
        }
        next := add(offset, length)
      }
    }
  }
}
