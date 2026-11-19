// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../PLONK.sol";

/// @dev Thin wrapper exposing PlonkVerifier for testing.
contract PlonkHarness {
  function proofLayoutIdentifier() external pure returns (bytes32) {
    return PlonkVerifier.PROOF_LAYOUT_IDENTIFIER;
  }

  function domainSeparators() external pure returns (bytes32[2] memory) {
    return [PlonkVerifier.TRANSCRIPT_DST, PlonkVerifier.XI_DST];
  }

  function verify(
    PlonkCircuit calldata circuit,
    bytes calldata proof
  ) external view returns (PlonkProof memory) {
    return PlonkVerifier.verify(circuit, proof);
  }

  /// @dev Verifies like `verify` but discards the results, so that the gas cost of a call is only
  ///   that of the verification and of the calldata, without encoding the results (for benchmarks).
  function check(PlonkCircuit calldata circuit, bytes calldata proof) external view {
    PlonkVerifier.verify(circuit, proof);
  }

  /// @dev Verifies like `check` and returns the gas spent by the verification alone, excluding the
  ///   transaction, its calldata, and the decoding of the arguments (for benchmarks).
  function verificationGas(
    PlonkCircuit calldata circuit,
    bytes calldata proof
  ) external view returns (uint256 gas) {
    PlonkCircuit memory decodedCircuit = circuit;
    gas = gasleft();
    PlonkVerifier.verify(decodedCircuit, proof);
    gas -= gasleft();
  }
}
