// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "../BlueSky.sol";

/// @dev Thin wrapper exposing ScalarMethods internals for testing.
contract BlueSkyHarness {
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return ScalarMethods.add(Scalar(a), Scalar(b)).value;
    }

    function sub(uint256 a, uint256 b) external pure returns (uint256) {
        return ScalarMethods.sub(Scalar(a), Scalar(b)).value;
    }

    function mul(uint256 a, uint256 b) external pure returns (uint256) {
        return ScalarMethods.mul(Scalar(a), Scalar(b)).value;
    }

    function neg(uint256 a) external pure returns (uint256) {
        return ScalarMethods.neg(Scalar(a)).value;
    }

    function pow(uint256 a, uint256 exponent) external view returns (uint256) {
        return ScalarMethods.pow(Scalar(a), exponent).value;
    }

    function inv(uint256 a) external view returns (uint256) {
        return ScalarMethods.inv(Scalar(a)).value;
    }
}
