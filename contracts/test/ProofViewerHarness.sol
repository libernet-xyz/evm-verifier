// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

import "../ProofViewer.sol";
import "./TestLayout.sol";

/// @dev Thin wrapper exposing ProofViewerMethods for testing. All the methods but `open` expect
///   SCPF data with `TEST_LAYOUT_IDENTIFIER`.
contract ProofViewerHarness {
  using ProofViewerMethods for ProofViewer;

  /// @dev Opens `data` expecting `layoutIdentifier`, and returns the pool size and the offset of
  ///   the stream in `data`.
  function open(
    bytes calldata data,
    bytes32 layoutIdentifier
  ) external pure returns (uint256 poolSize, uint256 stream) {
    uint256 start;
    assembly {
      start := data.offset
    }
    ProofViewer memory viewer = ProofViewerMethods.open(data, layoutIdentifier);
    return (viewer.poolSize, viewer.cursor - start);
  }

  /// @dev Reads `count` varints from the stream and returns them along with the number of bytes
  ///   left in the data.
  function popVarints(
    bytes calldata data,
    uint256 count
  ) external pure returns (uint256[] memory values, uint256 left) {
    ProofViewer memory viewer = ProofViewerMethods.open(data, TEST_LAYOUT_IDENTIFIER);
    values = new uint256[](count);
    for (uint256 i = 0; i < count; i++) {
      values[i] = viewer.popVarint();
    }
    left = viewer.end - viewer.cursor;
  }

  /// @dev Reads a varint and an inline word from the stream, then closes the data.
  function popVarintAndInlineWord(
    bytes calldata data
  ) external pure returns (uint256 varint, uint256 word) {
    ProofViewer memory viewer = ProofViewerMethods.open(data, TEST_LAYOUT_IDENTIFIER);
    varint = viewer.popVarint();
    word = viewer.popInlineWord();
    viewer.close();
  }

  /// @dev Reads `count` pool words referred to by the stream, then closes the data.
  function popPoolWords(
    bytes calldata data,
    uint256 count
  ) external pure returns (bytes32[] memory words) {
    ProofViewer memory viewer = ProofViewerMethods.open(data, TEST_LAYOUT_IDENTIFIER);
    words = new bytes32[](count);
    for (uint256 i = 0; i < count; i++) {
      words[i] = viewer.popPoolWord();
    }
    viewer.close();
  }

  /// @dev Reads `count` inline words from the stream into an array, and returns them along with
  ///   the offset of the first one in `data`, then closes the data.
  function popWords(
    bytes calldata data,
    uint256 count
  ) external pure returns (uint256[] memory words, uint256 offset) {
    uint256 start;
    assembly {
      start := data.offset
    }
    ProofViewer memory viewer = ProofViewerMethods.open(data, TEST_LAYOUT_IDENTIFIER);
    offset = viewer.cursor - start;
    words = viewer.popWords(count);
    viewer.close();
  }

  /// @dev Skips `count` inline words of the stream and returns the offset of the first one in
  ///   `data`, then closes the data.
  function skipWords(bytes calldata data, uint256 count) external pure returns (uint256) {
    uint256 start;
    assembly {
      start := data.offset
    }
    ProofViewer memory viewer = ProofViewerMethods.open(data, TEST_LAYOUT_IDENTIFIER);
    uint256 offset = viewer.skipWords(count);
    viewer.close();
    return offset - start;
  }

  /// @dev Opens and closes the data without reading anything from the stream.
  function close(bytes calldata data) external pure {
    ProofViewerMethods.open(data, TEST_LAYOUT_IDENTIFIER).close();
  }
}
