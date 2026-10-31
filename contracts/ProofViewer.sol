// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @notice A cursor over a proof encoded in the calldata format of the `calldata` crate (see
///   `tools/calldata`).
/// @dev The proof is `varint(pool size) || pool || heap`. The pool holds 32-byte words, the hashes
///   of the proof. The heap holds the rest of the proof in order: small integers as varints, field
///   elements as inline 32-byte big-endian words, and hashes as the varint indices of their pool
///   words.
///
///   Varints are big-endian with a prefix that encodes their length: the number of leading one
///   bits of the first byte is the number of bytes that follow it, so 1 byte holds 7 bits, 2 bytes
///   hold 14 bits, and so on up to 8 bytes holding 56 bits. Values of 57 bits or more take 9 bytes:
///   `0xff` followed by the 64-bit value. Like protobuf varints, non-minimal encodings are
///   accepted.
///
///   The viewer reads the calldata in place and only keeps offsets into it. Reading doesn't check
///   the end of the proof: past it, the viewer reads whatever follows in the calldata, or zeros
///   past the end of the calldata. Callers must invoke `close` after reading the whole heap, which
///   reverts if the reads went past the end or stopped before it.
struct ProofViewer {
    /// @dev The calldata offset of the first word of the pool.
    uint256 pool;
    /// @dev The number of words of the pool.
    uint256 poolSize;
    /// @dev The calldata offset of the next varint or inline word to read in the heap.
    uint256 cursor;
    /// @dev The calldata offset of the end of the proof.
    uint256 end;
}

/// @title ProofViewerMethods
/// @notice Decodes proofs encoded in the calldata format of the `calldata` crate (see
///   `ProofViewer`).
library ProofViewerMethods {
    /// @dev Reverted when the pool or the heap extend past the end of the proof.
    error TruncatedProof();

    /// @dev Reverted when the proof continues after the end of the heap.
    error TrailingData(uint256 length);

    /// @dev Reverted when a pool index is out of range.
    error InvalidPoolIndex(uint256 index, uint256 poolSize);

    /// @notice Opens a proof, returning a viewer whose cursor is at the beginning of the heap.
    function open(bytes calldata proof) internal pure returns (ProofViewer memory viewer) {
        uint256 start;
        uint256 end;
        assembly {
            start := proof.offset
            end := add(proof.offset, proof.length)
        }
        (uint256 poolSize, uint256 pool) = _readVarint(start);
        // No overflow: `pool` is a calldata offset and `poolSize` has at most 64 bits.
        uint256 heap;
        unchecked {
            heap = pool + (poolSize << 5);
        }
        if (heap > end) {
            revert TruncatedProof();
        }
        viewer = ProofViewer({pool: pool, poolSize: poolSize, cursor: heap, end: end});
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

    /// @notice Reads the next varint of the heap.
    function popVarint(ProofViewer memory self) internal pure returns (uint256 value) {
        uint256 next;
        (value, next) = _readVarint(self.cursor);
        self.cursor = next;
    }

    /// @notice Reads the next inline word of the heap.
    function popWord(ProofViewer memory self) internal pure returns (uint256 word) {
        uint256 cursor = self.cursor;
        assembly {
            word := calldataload(cursor)
        }
        unchecked {
            self.cursor = cursor + 32;
        }
    }

    /// @notice Reads the next varint of the heap and returns the pool word whose index it is.
    function popPoolWord(ProofViewer memory self) internal pure returns (bytes32) {
        return poolWord(self, popVarint(self));
    }

    /// @notice Skips the next `count` inline words of the heap and returns the calldata offset of
    ///   the first one, so that the caller can read them in place.
    function skipWords(
        ProofViewer memory self,
        uint256 count
    ) internal pure returns (uint256 offset) {
        offset = self.cursor;
        self.cursor = offset + count * 32;
    }

    /// @notice Reads the next `count` inline words of the heap into a new array.
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

    /// @notice Checks that the heap was read exactly up to the end of the proof, reverting
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
                    value := and(
                        shr(sub(256, shl(3, length)), word),
                        sub(shl(mul(7, length), 1), 1)
                    )
                }
                next := add(offset, length)
            }
        }
    }
}
