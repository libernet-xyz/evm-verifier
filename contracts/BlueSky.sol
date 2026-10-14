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

    /// @dev The 2-adicity of P-1: P-1 = 2^62 * m for odd m.
    uint256 constant S = 62;

    /// @dev The additive identity.
    uint256 constant ZERO = 0;

    /// @dev The multiplicative identity.
    uint256 constant ONE = 1;

    /// @dev The largest field element, p - 1 (that is, -1).
    uint256 constant MAX =
        0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000000;

    /// @dev The multiplicative generator of the field, which is also a quadratic non-residue.
    uint256 constant MULTIPLICATIVE_GENERATOR = 5;

    /// @dev The generator raised to 2^S, i.e. 5^(2^62). It generates the subgroup of odd order
    ///   (P-1)/2^S.
    uint256 constant DELTA =
        0x232680e97f4b6251c95edefd145053d6dea23905b503a1002987caddeb54cdce;

    /// @dev The exponent of the S-box x -> x^ALPHA used by the Poseidon hash over this field.
    uint256 constant ALPHA = 5;

    /// @dev The 3-adicity of P-1: P-1 = 3^39 * m for m not divisible by 3.
    uint256 constant T = 39;

    /// @dev The multiplicative inverse of 3.
    uint256 constant THREE_INV =
        0x55555555555555555555555555555554044d3ea1bf1238da8000000000000001;

    /// @dev The primitive 3^39-th root of unity in the BlueSky field.
    uint256 constant THREE_ADIC_ROOT_OF_UNITY =
        0x1b6292b3a6f8a32da98705fee2d66e8fe35f48642a417a72f1a4ca414adfd9e6;

    /// @dev Inverse of the primitive 3^39-th root of unity.
    uint256 constant THREE_ADIC_ROOT_OF_UNITY_INV =
        0x4d369d8e1ff761fca979a0ffb5545471ceae8164a047dff8b5679e11c5dfdf72;

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

    /// @notice Returns the square of a field element.
    /// @param a The operand, in [0, p).
    /// @return The field element a^2 mod p.
    function square(uint256 a) internal pure returns (uint256) {
        return mulmod(a, a, P);
    }

    /// @notice Returns twice a field element.
    /// @param a The operand, in [0, p).
    /// @return The field element 2a mod p.
    function double(uint256 a) internal pure returns (uint256) {
        return addmod(a, a, P);
    }

    /// @notice Returns the cube of a field element.
    /// @param a The operand, in [0, p).
    /// @return The field element a^3 mod p.
    function cube(uint256 a) internal pure returns (uint256) {
        return mulmod(mulmod(a, a, P), a, P);
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

    /// @notice Returns the quotient of two field elements.
    /// @dev Calls the `modexp` precompile through `inv`.
    /// @param a The dividend, in [0, p).
    /// @param b The divisor, in [0, p). Must be non-zero.
    /// @return The field element a * b^(-1) mod p.
    function div(uint256 a, uint256 b) internal view returns (uint256) {
        return mulmod(a, inv(b), P);
    }

    /// @notice Inverts all the provided values in place using Montgomery batch inversion.
    /// @dev Costs a single call to the `modexp` precompile plus three multiplications per value,
    ///   instead of one precompile call per value. Reverts with `ZeroDivisor` if any value is zero.
    /// @dev Only worth it for two or more values: for a single value it costs more than `inv`
    ///   because of the extra array allocation and loop. Measured with the optimizer enabled
    ///   under the Osaka gas schedule (EIP-7883 `modexp` pricing), where `inv` costs about 4.6k
    ///   gas: one value costs 5.4k with `invBatch` versus 4.6k with `inv`, while two values cost
    ///   6.2k versus 9.2k. The break-even point is therefore N = 2, and the saving grows to about
    ///   60% at N = 4 and about 80% at N = 256. Under the Prague schedule (EIP-2565 pricing) `inv`
    ///   costs about 1.9k gas, so the break-even is still N = 2 but the margin is thin there (3.5k
    ///   versus 3.8k). Results depend on the optimizer and on the chain's `modexp` pricing.
    /// @param values The field elements to invert, each in [0, p). Overwritten with their inverses.
    function invBatch(uint256[] memory values) internal view {
        uint256 length = values.length;
        if (length == 0) {
            return;
        }
        uint256[] memory partialProducts = new uint256[](length);
        uint256 accumulator = 1;
        for (uint256 i = 0; i < length; i++) {
            partialProducts[i] = accumulator;
            accumulator = mulmod(accumulator, values[i], P);
        }
        uint256 inverse = inv(accumulator);
        for (uint256 i = length; i > 0; i--) {
            uint256 input = values[i - 1];
            values[i - 1] = mulmod(partialProducts[i - 1], inverse, P);
            inverse = mulmod(inverse, input, P);
        }
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
