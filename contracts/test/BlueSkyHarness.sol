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

    function square(uint256 a) external pure returns (uint256) {
        return BlueSky.square(a);
    }

    function double(uint256 a) external pure returns (uint256) {
        return BlueSky.double(a);
    }

    function cube(uint256 a) external pure returns (uint256) {
        return BlueSky.cube(a);
    }

    function div(uint256 a, uint256 b) external view returns (uint256) {
        return BlueSky.div(a, b);
    }

    function invBatch(uint256[] calldata values) external view returns (uint256[] memory) {
        uint256[] memory result = values;
        BlueSky.invBatch(result);
        return result;
    }

    function zero() external pure returns (uint256) {
        return BlueSky.ZERO;
    }

    function one() external pure returns (uint256) {
        return BlueSky.ONE;
    }

    function max() external pure returns (uint256) {
        return BlueSky.MAX;
    }

    function multiplicativeGenerator() external pure returns (uint256) {
        return BlueSky.MULTIPLICATIVE_GENERATOR;
    }

    function delta() external pure returns (uint256) {
        return BlueSky.DELTA;
    }

    function alpha() external pure returns (uint256) {
        return BlueSky.ALPHA;
    }

    function s() external pure returns (uint256) {
        return BlueSky.S;
    }

    function t() external pure returns (uint256) {
        return BlueSky.T;
    }

    function p() external pure returns (uint256) {
        return BlueSky.P;
    }

    function pMinus2() external pure returns (uint256) {
        return BlueSky.P_MINUS_2;
    }

    function twoInv() external pure returns (uint256) {
        return BlueSky.TWO_INV;
    }

    function threeInv() external pure returns (uint256) {
        return BlueSky.THREE_INV;
    }

    function rootOfUnity() external pure returns (uint256) {
        return BlueSky.TWO_ADIC_ROOT_OF_UNITY;
    }

    function rootOfUnityInv() external pure returns (uint256) {
        return BlueSky.TWO_ADIC_ROOT_OF_UNITY_INV;
    }

    function threeAdicRootOfUnity() external pure returns (uint256) {
        return BlueSky.THREE_ADIC_ROOT_OF_UNITY;
    }

    function threeAdicRootOfUnityInv() external pure returns (uint256) {
        return BlueSky.THREE_ADIC_ROOT_OF_UNITY_INV;
    }
}
