// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../BlueSky.sol";

/// @dev Thin wrapper exposing BlueSky internals for testing.
contract BlueSkyHarness {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return BlueSky.add(a, b);
    }

    function sub(uint256 a, uint256 b) external pure returns (uint256) {
        return BlueSky.sub(a, b);
    }

    function mul(uint256 a, uint256 b) external pure returns (uint256) {
        return BlueSky.mul(a, b);
    }

    function neg(uint256 a) external pure returns (uint256) {
        return BlueSky.neg(a);
    }

    function pow(uint256 a, uint256 exponent) external view returns (uint256) {
        return BlueSky.pow(a, exponent);
    }

    function inv(uint256 a) external view returns (uint256) {
        return BlueSky.inv(a);
    }
}
