// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../ProofViewer.sol";

/// @dev Thin wrapper exposing ProofViewerMethods for testing.
contract ProofViewerHarness {
    using ProofViewerMethods for ProofViewer;

    function open(bytes calldata proof) external pure returns (uint256 poolSize, uint256 heap) {
        uint256 start;
        assembly {
            start := proof.offset
        }
        ProofViewer memory viewer = ProofViewerMethods.open(proof);
        return (viewer.poolSize, viewer.cursor - start);
    }

    /// @dev Returns the pool word at `index`.
    function poolWord(bytes calldata proof, uint256 index) external pure returns (bytes32) {
        return ProofViewerMethods.open(proof).poolWord(index);
    }

    /// @dev Reads `count` varints from the heap and returns them along with the number of bytes
    ///   left in the proof.
    function popVarints(
        bytes calldata proof,
        uint256 count
    ) external pure returns (uint256[] memory values, uint256 left) {
        ProofViewer memory viewer = ProofViewerMethods.open(proof);
        values = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            values[i] = viewer.popVarint();
        }
        left = viewer.end - viewer.cursor;
    }

    /// @dev Reads a varint and an inline word from the heap, then closes the proof.
    function popVarintAndWord(
        bytes calldata proof
    ) external pure returns (uint256 varint, uint256 word) {
        ProofViewer memory viewer = ProofViewerMethods.open(proof);
        varint = viewer.popVarint();
        word = viewer.popWord();
        viewer.close();
    }

    /// @dev Reads `count` pool words referred to by the heap, then closes the proof.
    function popPoolWords(
        bytes calldata proof,
        uint256 count
    ) external pure returns (bytes32[] memory words) {
        ProofViewer memory viewer = ProofViewerMethods.open(proof);
        words = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            words[i] = viewer.popPoolWord();
        }
        viewer.close();
    }

    /// @dev Reads `count` inline words from the heap into an array, and returns them along with
    ///   the heap offset of the first one, then closes the proof.
    function popWords(
        bytes calldata proof,
        uint256 count
    ) external pure returns (uint256[] memory words, uint256 offset) {
        uint256 start;
        assembly {
            start := proof.offset
        }
        ProofViewer memory viewer = ProofViewerMethods.open(proof);
        offset = viewer.cursor - start;
        words = viewer.popWords(count);
        viewer.close();
    }

    /// @dev Skips `count` inline words of the heap and returns the proof offset of the first one,
    ///   then closes the proof.
    function skipWords(bytes calldata proof, uint256 count) external pure returns (uint256) {
        uint256 start;
        assembly {
            start := proof.offset
        }
        ProofViewer memory viewer = ProofViewerMethods.open(proof);
        uint256 offset = viewer.skipWords(count);
        viewer.close();
        return offset - start;
    }

    /// @dev Opens and closes a proof without reading anything from the heap.
    function close(bytes calldata proof) external pure {
        ProofViewerMethods.open(proof).close();
    }
}
