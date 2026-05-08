// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title BlueSky
/// @notice Arithmetic library for the 255-bit BlueSky prime field.
/// @dev The prime is p = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001.
/// @dev All inputs and outputs are canonical integers in [0, p).
/// @dev Functions that call the `modexp` precompile (address 0x05) are marked `view` rather than
///   `pure`.
library BlueSky {
    /// @dev Reverted when zero is passed to `inv`.
    error ZeroDivisor();

    /// @notice The BlueSky prime p.
    uint256 constant P =
        0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001;

    /// @dev p - 2, the exponent used by Fermat's little theorem for inversion:
    ///   a^(p-2) ≡ a^(-1) (mod p) for any a ≠ 0.
    uint256 constant P_MINUS_2 =
        0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547bfffffffffffffff;

    /// @dev (P+1)/2 mod P — the multiplicative inverse of 2.
    uint256 constant TWO_INV =
        0x3fffffffffffffffffffffffffffffff0339eef94f4daaa3e000000000000001;

    /// @dev The primitive 2^62-th root of unity in the BlueSky field.
    uint256 constant ROOT_OF_UNITY =
        0x2772569d549e1249ca6891eceba43568f6e0a747a2afe898b3977ca1a5bbfc9c;

    /// @dev Inverse of the primitive 2^62-th root of unity.
    uint256 constant ROOT_OF_UNITY_INV =
        0x76def406f046ef5ee7eeecd2c4e6ecd7cdedc4e2bcf6b19f1420121cd00b4cdb;

    /// @dev The 2-adicity of P-1: P-1 = 2^62 * T for odd T.
    uint256 constant S = 62;

    /// @notice Returns the sum of two field elements.
    /// @param a First operand, in [0, p).
    /// @param b Second operand, in [0, p).
    /// @return The field element (a + b) mod p.
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, P);
    }

    /// @notice Returns the difference of two field elements.
    /// @param a Minuend, in [0, p).
    /// @param b Subtrahend, in [0, p).
    /// @return The field element (a - b) mod p.
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        // P - b is in (0, P] and addmod uses infinite-precision addition,
        // so this is correct even when b == 0 (addmod(a, P, P) == a).
        return addmod(a, P - b, P);
    }

    /// @notice Returns the product of two field elements.
    /// @param a First operand, in [0, p).
    /// @param b Second operand, in [0, p).
    /// @return The field element (a * b) mod p.
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, P);
    }

    /// @notice Returns the additive inverse of a field element.
    /// @param a The operand, in [0, p).
    /// @return The field element (-a) mod p.
    function neg(uint256 a) internal pure returns (uint256) {
        return a == 0 ? 0 : P - a;
    }

    /// @notice Returns a raised to an integer power.
    /// @dev Calls the `modexp` precompile (EIP-198, address 0x05).
    /// @dev Follows the precompile's convention: 0^0 = 1.
    /// @param a The base, in [0, p).
    /// @param exponent The exponent (any uint256; implicitly reduced mod p-1 by Fermat).
    /// @return The field element a^exponent mod p.
    function pow(uint256 a, uint256 exponent) internal view returns (uint256) {
        return _modexp(a, exponent, P);
    }

    /// @notice Returns the multiplicative inverse of a field element.
    /// @dev Computed via Fermat's little theorem: a^(p-2) mod p. Calls the `modexp` precompile
    ///   (EIP-198, address 0x05).
    /// @param a The operand, in [0, p). Must be non-zero.
    /// @return The field element a^(-1) mod p.
    function inv(uint256 a) internal view returns (uint256) {
        if (a == 0) {
            revert ZeroDivisor();
        }
        return _modexp(a, P_MINUS_2, P);
    }

    /// @dev Calls the `modexp` precompile (EIP-198) for 256-bit inputs.
    function _modexp(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) internal view returns (uint256 result) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), base)
            mstore(add(ptr, 0x80), exponent)
            mstore(add(ptr, 0xa0), modulus)
            if iszero(staticcall(gas(), 5, ptr, 0xc0, ptr, 0x20)) {
                revert(0, 0)
            }
            result := mload(ptr)
        }
    }
}
