// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.34;

/// @dev The layout identifier of the SCPF data that the tests pass to the harnesses, other than
///   PLONK proofs: e.g. bare Merkle paths, or the openings of FRI queries.
bytes32 constant TEST_LAYOUT_IDENTIFIER = keccak256("test");
