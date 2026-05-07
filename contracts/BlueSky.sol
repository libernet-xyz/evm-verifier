// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @notice A field element of the BlueSky prime field.
/// @dev Stored as a canonical integer in `[0, p)` (no Montgomery).
struct Scalar {
    uint256 value;
}

/// @title ScalarMethods
/// @notice Arithmetic library for the 255-bit BlueSky prime field.
/// @dev The prime is p = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001.
/// @dev All inputs and outputs are assumed to be in the canonical range [0, p).
/// @dev Functions that call the `modexp` precompile (address 0x05) need to be marked `view` rather
///   than `pure`.
library ScalarMethods {
    /// @notice The BlueSky prime p.
    uint256 constant P =
        0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001;

    /// @dev p - 2, the exponent used by Fermat's little theorem for inversion:
    ///   a^(p-2) ≡ a^(-1) (mod p) for any a ≠ 0.
    uint256 constant P_MINUS_2 =
        0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547bfffffffffffffff;

    /// @notice Returns the sum of two field elements.
    /// @param a First operand, in [0, p).
    /// @param b Second operand, in [0, p).
    /// @return The field element (a + b) mod p.
    function add(
        Scalar memory a,
        Scalar memory b
    ) internal pure returns (Scalar memory) {
        return Scalar(addmod(a.value, b.value, P));
    }

    /// @notice Returns the difference of two field elements.
    /// @param a Minuend, in [0, p).
    /// @param b Subtrahend, in [0, p).
    /// @return The field element (a - b) mod p.
    function sub(
        Scalar memory a,
        Scalar memory b
    ) internal pure returns (Scalar memory) {
        // P - b.value is in (0, P] and addmod uses infinite-precision addition,
        // so this is correct even when b.value == 0 (addmod(a, P, P) == a).
        return Scalar(addmod(a.value, P - b.value, P));
    }

    /// @notice Returns the product of two field elements.
    /// @param a First operand, in [0, p).
    /// @param b Second operand, in [0, p).
    /// @return The field element (a * b) mod p.
    function mul(
        Scalar memory a,
        Scalar memory b
    ) internal pure returns (Scalar memory) {
        return Scalar(mulmod(a.value, b.value, P));
    }

    /// @notice Returns the additive inverse of a field element.
    /// @param a The operand, in [0, p).
    /// @return The field element (-a) mod p, i.e. 0 if a == 0, else p - a.
    function neg(Scalar memory a) internal pure returns (Scalar memory) {
        return a.value == 0 ? Scalar(0) : Scalar(P - a.value);
    }

    /// @notice Returns a raised to an integer power.
    /// @dev Calls the `modexp` precompile (EIP-198, address 0x05).
    /// @dev Follows the precompile's convention: 0^0 = 1.
    /// @param a The base, in [0, p).
    /// @param exponent The exponent (any uint256; implicitly reduced mod p-1 by Fermat).
    /// @return The field element a^exponent mod p.
    function pow(
        Scalar memory a,
        uint256 exponent
    ) internal view returns (Scalar memory) {
        return Scalar(_modexp(a.value, exponent, P));
    }

    /// @notice Returns the multiplicative inverse of a field element.
    /// @dev Computed via Fermat's little theorem: a^(p-2) mod p. Calls the `modexp` precompile
    ///   (EIP-198, address 0x05).
    /// @param a The operand, in [0, p). Must be non-zero.
    /// @return The field element a^(-1) mod p.
    function inv(Scalar memory a) internal view returns (Scalar memory) {
        require(a.value != 0, "zero");
        return Scalar(_modexp(a.value, P_MINUS_2, P));
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
