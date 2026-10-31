// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../Keccak256Hash.sol";

/// @dev Thin wrapper exposing Keccak256Hash internals for testing.
contract Keccak256HashHarness {
    function hash(uint256[] calldata inputs) external pure returns (bytes32) {
        return Keccak256Hash.hash(inputs);
    }

    function hashBinary(bytes32 left, bytes32 right) external pure returns (bytes32) {
        return Keccak256Hash.hashBinary(left, right);
    }

    function hashTranscript(
        bytes32 dst,
        bytes32[] calldata transcript
    ) external pure returns (bytes32) {
        return Keccak256Hash.hashTranscript(dst, transcript);
    }

    function challenge(bytes32 dst, bytes32[] calldata transcript) external pure returns (uint256) {
        return Keccak256Hash.challenge(dst, transcript);
    }
}
