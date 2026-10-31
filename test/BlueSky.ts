import { expect } from "chai";
import { network } from "hardhat";
import type { BlueSkyHarness } from "../types/ethers-contracts";

const { ethers } = await network.create();

const P = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001n;

const TWO_INV = 0x3fffffffffffffffffffffffffffffff0339eef94f4daaa3e000000000000001n;

const THREE_INV = 0x55555555555555555555555555555554044d3ea1bf1238da8000000000000001n;

const ROOT_OF_UNITY = 0x2772569d549e1249ca6891eceba43568f6e0a747a2afe898b3977ca1a5bbfc9cn;

const ROOT_OF_UNITY_INV = 0x76def406f046ef5ee7eeecd2c4e6ecd7cdedc4e2bcf6b19f1420121cd00b4cdbn;

const DELTA = 0x232680e97f4b6251c95edefd145053d6dea23905b503a1002987caddeb54cdcen;

const THREE_ADIC_ROOT_OF_UNITY =
  0x1b6292b3a6f8a32da98705fee2d66e8fe35f48642a417a72f1a4ca414adfd9e6n;

const THREE_ADIC_ROOT_OF_UNITY_INV =
  0x4d369d8e1ff761fca979a0ffb5545471ceae8164a047dff8b5679e11c5dfdf72n;

/** Reference modular exponentiation used to cross-check the contract. */
function modPow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  base %= P;
  while (exponent > 0n) {
    if (exponent & 1n) {
      result = (result * base) % P;
    }
    base = (base * base) % P;
    exponent >>= 1n;
  }
  return result;
}

/** Reference modular inverse (Fermat) used to cross-check the contract. */
function modInv(value: bigint): bigint {
  return modPow(value, P - 2n);
}

/** Some arbitrary field elements spanning small, mid-range, and near-modulus values. */
const SAMPLES = [
  1n,
  2n,
  3n,
  5n,
  0xdeadbeefn,
  2n ** 64n + 1n,
  2n ** 128n - 1n,
  2n ** 200n + 12345n,
  P >> 1n,
  P - 3n,
  P - 2n,
  P - 1n,
];

describe("BlueSky field arithmetic", function () {
  let harness: BlueSkyHarness;

  before(async function () {
    harness = await ethers.deployContract("BlueSkyHarness");
  });

  describe("constants", function () {
    it("P is the BlueSky modulus", async function () {
      expect(await harness.p()).to.equal(P);
    });

    it("P_MINUS_2 = P - 2", async function () {
      expect(await harness.pMinus2()).to.equal(P - 2n);
    });

    it("ZERO = 0 and ONE = 1", async function () {
      expect(await harness.zero()).to.equal(0n);
      expect(await harness.one()).to.equal(1n);
    });

    it("MAX = P - 1", async function () {
      expect(await harness.max()).to.equal(P - 1n);
    });

    it("MULTIPLICATIVE_GENERATOR = 5", async function () {
      expect(await harness.multiplicativeGenerator()).to.equal(5n);
    });

    it("MULTIPLICATIVE_GENERATOR is a quadratic non-residue", async function () {
      const generator = await harness.multiplicativeGenerator();
      expect(await harness.pow(generator, (P - 1n) / 2n)).to.equal(P - 1n);
    });

    it("MULTIPLICATIVE_GENERATOR has full order p - 1", async function () {
      // p - 1 = 2^62 * 3^39 * 31 * 47491 * 20313611 * 117579359 * 880985987837994013. An element
      // has full order iff raising it to (p-1)/q yields something other than 1 for every prime
      // factor q of p - 1.
      const generator = await harness.multiplicativeGenerator();
      const primeFactors = [2n, 3n, 31n, 47491n, 20313611n, 117579359n, 880985987837994013n];
      for (const q of primeFactors) {
        expect(await harness.pow(generator, (P - 1n) / q)).to.not.equal(1n);
      }
    });

    it("ALPHA = 5", async function () {
      expect(await harness.alpha()).to.equal(5n);
    });

    it("S = 62 and 2^S divides P - 1 exactly", async function () {
      const s = await harness.s();
      expect(s).to.equal(62n);
      expect((P - 1n) % 2n ** s).to.equal(0n);
      expect((P - 1n) % 2n ** (s + 1n)).to.not.equal(0n);
    });

    it("T = 39 and 3^T divides P - 1 exactly", async function () {
      const t = await harness.t();
      expect(t).to.equal(39n);
      expect((P - 1n) % 3n ** t).to.equal(0n);
      expect((P - 1n) % 3n ** (t + 1n)).to.not.equal(0n);
    });

    it("TWO_INV matches its expected value", async function () {
      expect(await harness.twoInv()).to.equal(TWO_INV);
    });

    it("TWO_INV * 2 = 1", async function () {
      const result = await harness.mul(await harness.twoInv(), 2n);
      expect(result).to.equal(1n);
    });

    it("THREE_INV matches its expected value", async function () {
      expect(await harness.threeInv()).to.equal(THREE_INV);
    });

    it("THREE_INV * 3 = 1", async function () {
      const result = await harness.mul(await harness.threeInv(), 3n);
      expect(result).to.equal(1n);
    });

    it("ROOT_OF_UNITY matches its expected value", async function () {
      expect(await harness.rootOfUnity()).to.equal(ROOT_OF_UNITY);
    });

    it("ROOT_OF_UNITY^(2^62) = 1 (order divides 2^62)", async function () {
      const result = await harness.pow(await harness.rootOfUnity(), 2n ** 62n);
      expect(result).to.equal(1n);
    });

    it("ROOT_OF_UNITY^(2^61) != 1 (primitive, order is exactly 2^62)", async function () {
      const result = await harness.pow(await harness.rootOfUnity(), 2n ** 61n);
      expect(result).to.not.equal(1n);
    });

    it("ROOT_OF_UNITY_INV matches its expected value", async function () {
      expect(await harness.rootOfUnityInv()).to.equal(ROOT_OF_UNITY_INV);
    });

    it("ROOT_OF_UNITY * ROOT_OF_UNITY_INV = 1", async function () {
      const result = await harness.mul(await harness.rootOfUnity(), await harness.rootOfUnityInv());
      expect(result).to.equal(1n);
    });

    it("DELTA matches its expected value", async function () {
      expect(await harness.delta()).to.equal(DELTA);
    });

    it("DELTA = MULTIPLICATIVE_GENERATOR^(2^S)", async function () {
      const generator = await harness.multiplicativeGenerator();
      const s = await harness.s();
      expect(await harness.delta()).to.equal(await harness.pow(generator, 2n ** s));
    });

    it("DELTA^((P-1)/2^S) = 1 (order divides the odd part of P - 1)", async function () {
      const s = await harness.s();
      const result = await harness.pow(await harness.delta(), (P - 1n) / 2n ** s);
      expect(result).to.equal(1n);
    });

    it("THREE_ADIC_ROOT_OF_UNITY matches its expected value", async function () {
      expect(await harness.threeAdicRootOfUnity()).to.equal(THREE_ADIC_ROOT_OF_UNITY);
    });

    it("THREE_ADIC_ROOT_OF_UNITY^(3^39) = 1 (order divides 3^39)", async function () {
      const root = await harness.threeAdicRootOfUnity();
      expect(await harness.pow(root, 3n ** 39n)).to.equal(1n);
    });

    it("THREE_ADIC_ROOT_OF_UNITY^(3^38) != 1 (primitive, order is 3^39)", async function () {
      const root = await harness.threeAdicRootOfUnity();
      expect(await harness.pow(root, 3n ** 38n)).to.not.equal(1n);
    });

    it("THREE_ADIC_ROOT_OF_UNITY_INV matches its expected value", async function () {
      expect(await harness.threeAdicRootOfUnityInv()).to.equal(THREE_ADIC_ROOT_OF_UNITY_INV);
    });

    it("THREE_ADIC_ROOT_OF_UNITY * THREE_ADIC_ROOT_OF_UNITY_INV = 1", async function () {
      const result = await harness.mul(
        await harness.threeAdicRootOfUnity(),
        await harness.threeAdicRootOfUnityInv(),
      );
      expect(result).to.equal(1n);
    });
  });

  describe("add", function () {
    it("0 + 0 = 0", async function () {
      const result = await harness.add(0n, 0n);
      expect(result).to.equal(0n);
    });

    it("1 + 0 = 1 (additive identity)", async function () {
      const result = await harness.add(1n, 0n);
      expect(result).to.equal(1n);
    });

    it("0 + 1 = 1 (commutativity)", async function () {
      const result = await harness.add(0n, 1n);
      expect(result).to.equal(1n);
    });

    it("(p-1) + 1 = 0 (wrap-around)", async function () {
      const result = await harness.add(P - 1n, 1n);
      expect(result).to.equal(0n);
    });

    it("(p-1) + (p-1) = p-2 (double wrap-around)", async function () {
      const result = await harness.add(P - 1n, P - 1n);
      expect(result).to.equal(P - 2n);
    });
  });

  describe("sub", function () {
    it("0 - 0 = 0", async function () {
      const result = await harness.sub(0n, 0n);
      expect(result).to.equal(0n);
    });

    it("5 - 5 = 0", async function () {
      const result = await harness.sub(5n, 5n);
      expect(result).to.equal(0n);
    });

    it("3 - 1 = 2", async function () {
      const result = await harness.sub(3n, 1n);
      expect(result).to.equal(2n);
    });

    it("0 - 1 = p-1 (wrap-around)", async function () {
      const result = await harness.sub(0n, 1n);
      expect(result).to.equal(P - 1n);
    });

    it("1 - (p-1) = 2 (wrap-around)", async function () {
      const result = await harness.sub(1n, P - 1n);
      expect(result).to.equal(2n);
    });
  });

  describe("mul", function () {
    it("0 * 5 = 0", async function () {
      const result = await harness.mul(0n, 5n);
      expect(result).to.equal(0n);
    });

    it("1 * 7 = 7 (multiplicative identity)", async function () {
      const result = await harness.mul(1n, 7n);
      expect(result).to.equal(7n);
    });

    it("3 * 4 = 12", async function () {
      const result = await harness.mul(3n, 4n);
      expect(result).to.equal(12n);
    });

    it("(p-1) * (p-1) = 1 ((-1)^2 = 1)", async function () {
      const result = await harness.mul(P - 1n, P - 1n);
      expect(result).to.equal(1n);
    });

    it("(p-1) * 3 = p-3 ((-1)*3 = -3)", async function () {
      const result = await harness.mul(P - 1n, 3n);
      expect(result).to.equal(P - 3n);
    });
  });

  describe("neg", function () {
    it("neg(0) = 0", async function () {
      const result = await harness.neg(0n);
      expect(result).to.equal(0n);
    });

    it("neg(1) = p-1", async function () {
      const result = await harness.neg(1n);
      expect(result).to.equal(P - 1n);
    });

    it("neg(p-1) = 1", async function () {
      const result = await harness.neg(P - 1n);
      expect(result).to.equal(1n);
    });
  });

  describe("pow", function () {
    it("a^0 = 1 for nonzero a", async function () {
      const result = await harness.pow(7n, 0n);
      expect(result).to.equal(1n);
    });

    it("0^0 = 1 (modexp precompile convention)", async function () {
      const result = await harness.pow(0n, 0n);
      expect(result).to.equal(1n);
    });

    it("0^n = 0 for n > 0", async function () {
      const result = await harness.pow(0n, 5n);
      expect(result).to.equal(0n);
    });

    it("a^1 = a", async function () {
      const result = await harness.pow(42n, 1n);
      expect(result).to.equal(42n);
    });

    it("2^10 = 1024", async function () {
      const result = await harness.pow(2n, 10n);
      expect(result).to.equal(1024n);
    });

    it("a^(p-1) = 1 for nonzero a (Fermat's little theorem)", async function () {
      const result = await harness.pow(3n, P - 1n);
      expect(result).to.equal(1n);
    });

    it("a^(p-2) = inv(a) (Fermat inversion)", async function () {
      const result = await harness.pow(2n, P - 2n);
      expect(result).to.equal(TWO_INV);
    });
  });

  describe("inv", function () {
    it("inv(1) = 1", async function () {
      const result = await harness.inv(1n);
      expect(result).to.equal(1n);
    });

    it("inv(p-1) = p-1 (inv(-1) = -1)", async function () {
      const result = await harness.inv(P - 1n);
      expect(result).to.equal(P - 1n);
    });

    it("inv(2) = (p+1)/2", async function () {
      const result = await harness.inv(2n);
      expect(result).to.equal(TWO_INV);
    });

    it("a * inv(a) = 1", async function () {
      const invFive = await harness.inv(5n);
      const result = await harness.mul(5n, invFive);
      expect(result).to.equal(1n);
    });

    it("reverts on zero input", async function () {
      await expect(harness.inv(0n)).to.be.revertedWithCustomError(harness, "ZeroDivisor");
    });
  });

  describe("square", function () {
    it("0^2 = 0", async function () {
      expect(await harness.square(0n)).to.equal(0n);
    });

    it("1^2 = 1", async function () {
      expect(await harness.square(1n)).to.equal(1n);
    });

    it("7^2 = 49", async function () {
      expect(await harness.square(7n)).to.equal(49n);
    });

    it("(p-1)^2 = 1", async function () {
      expect(await harness.square(P - 1n)).to.equal(1n);
    });

    it("(p-2)^2 = 4", async function () {
      expect(await harness.square(P - 2n)).to.equal(4n);
    });

    it("agrees with mul(a, a)", async function () {
      for (const a of SAMPLES) {
        expect(await harness.square(a)).to.equal(await harness.mul(a, a));
      }
    });

    it("agrees with the reference implementation", async function () {
      for (const a of SAMPLES) {
        expect(await harness.square(a)).to.equal((a * a) % P);
      }
    });
  });

  describe("double", function () {
    it("2*0 = 0", async function () {
      expect(await harness.double(0n)).to.equal(0n);
    });

    it("2*1 = 2", async function () {
      expect(await harness.double(1n)).to.equal(2n);
    });

    it("2 * TWO_INV = 1 (wrap-around)", async function () {
      expect(await harness.double(TWO_INV)).to.equal(1n);
    });

    it("2*(p-1) = p-2 (wrap-around)", async function () {
      expect(await harness.double(P - 1n)).to.equal(P - 2n);
    });

    it("agrees with add(a, a)", async function () {
      for (const a of SAMPLES) {
        expect(await harness.double(a)).to.equal(await harness.add(a, a));
      }
    });

    it("agrees with the reference implementation", async function () {
      for (const a of SAMPLES) {
        expect(await harness.double(a)).to.equal((2n * a) % P);
      }
    });
  });

  describe("cube", function () {
    it("0^3 = 0", async function () {
      expect(await harness.cube(0n)).to.equal(0n);
    });

    it("1^3 = 1", async function () {
      expect(await harness.cube(1n)).to.equal(1n);
    });

    it("3^3 = 27", async function () {
      expect(await harness.cube(3n)).to.equal(27n);
    });

    it("(p-1)^3 = p-1 ((-1)^3 = -1)", async function () {
      expect(await harness.cube(P - 1n)).to.equal(P - 1n);
    });

    it("agrees with mul(square(a), a)", async function () {
      for (const a of SAMPLES) {
        const squared = await harness.square(a);
        expect(await harness.cube(a)).to.equal(await harness.mul(squared, a));
      }
    });

    it("agrees with the reference implementation", async function () {
      for (const a of SAMPLES) {
        expect(await harness.cube(a)).to.equal((a * a * a) % P);
      }
    });

    it("cube of the 3-adic root of unity is a 3^38-th root of unity", async function () {
      const cubed = await harness.cube(THREE_ADIC_ROOT_OF_UNITY);
      expect(await harness.pow(cubed, 3n ** 38n)).to.equal(1n);
    });
  });

  describe("div", function () {
    it("0 / a = 0", async function () {
      expect(await harness.div(0n, 7n)).to.equal(0n);
    });

    it("a / 1 = a", async function () {
      expect(await harness.div(42n, 1n)).to.equal(42n);
    });

    it("a / a = 1", async function () {
      for (const a of SAMPLES) {
        expect(await harness.div(a, a)).to.equal(1n);
      }
    });

    it("1 / 2 = TWO_INV", async function () {
      expect(await harness.div(1n, 2n)).to.equal(TWO_INV);
    });

    it("1 / 3 = THREE_INV", async function () {
      expect(await harness.div(1n, 3n)).to.equal(THREE_INV);
    });

    it("12 / 4 = 3", async function () {
      expect(await harness.div(12n, 4n)).to.equal(3n);
    });

    it("(p-1) / (p-1) = 1 and 1 / (p-1) = p-1", async function () {
      expect(await harness.div(P - 1n, P - 1n)).to.equal(1n);
      expect(await harness.div(1n, P - 1n)).to.equal(P - 1n);
    });

    it("(a / b) * b = a", async function () {
      for (const a of SAMPLES) {
        for (const b of [2n, 17n, P - 5n]) {
          const quotient = await harness.div(a, b);
          expect(await harness.mul(quotient, b)).to.equal(a);
        }
      }
    });

    it("agrees with the reference implementation", async function () {
      for (const a of SAMPLES) {
        const b = SAMPLES[(SAMPLES.indexOf(a) + 3) % SAMPLES.length];
        expect(await harness.div(a, b)).to.equal((a * modInv(b)) % P);
      }
    });

    it("reverts on a zero divisor", async function () {
      await expect(harness.div(5n, 0n)).to.be.revertedWithCustomError(harness, "ZeroDivisor");
    });

    it("reverts on 0 / 0", async function () {
      await expect(harness.div(0n, 0n)).to.be.revertedWithCustomError(harness, "ZeroDivisor");
    });
  });

  describe("invBatch", function () {
    it("returns an empty array for empty input", async function () {
      expect(await harness.invBatch([])).to.deep.equal([]);
    });

    it("inverts a single element", async function () {
      expect(await harness.invBatch([2n])).to.deep.equal([TWO_INV]);
    });

    it("inverts a pair", async function () {
      expect(await harness.invBatch([2n, 3n])).to.deep.equal([TWO_INV, THREE_INV]);
    });

    it("inverts [1, p-1] to itself", async function () {
      expect(await harness.invBatch([1n, P - 1n])).to.deep.equal([1n, P - 1n]);
    });

    it("preserves the order of its inputs", async function () {
      const values = [5n, 3n, 2n, 7n, 11n];
      const result = await harness.invBatch(values);
      for (let i = 0; i < values.length; i++) {
        expect(result[i]).to.equal(modInv(values[i]));
      }
    });

    it("agrees with inv() on every element", async function () {
      const result = await harness.invBatch(SAMPLES);
      expect(result.length).to.equal(SAMPLES.length);
      for (let i = 0; i < SAMPLES.length; i++) {
        expect(result[i]).to.equal(await harness.inv(SAMPLES[i]));
      }
    });

    it("agrees with the reference implementation", async function () {
      const result = await harness.invBatch(SAMPLES);
      for (let i = 0; i < SAMPLES.length; i++) {
        expect(result[i]).to.equal(modInv(SAMPLES[i]));
      }
    });

    it("each output times its input is 1", async function () {
      const result = await harness.invBatch(SAMPLES);
      for (let i = 0; i < SAMPLES.length; i++) {
        expect(await harness.mul(result[i], SAMPLES[i])).to.equal(1n);
      }
    });

    it("handles repeated elements", async function () {
      const result = await harness.invBatch([4n, 4n, 4n]);
      const expected = modInv(4n);
      expect(result).to.deep.equal([expected, expected, expected]);
    });

    it("is an involution: inverting twice returns the original values", async function () {
      const once = await harness.invBatch(SAMPLES);
      const twice = await harness.invBatch([...once]);
      expect([...twice]).to.deep.equal(SAMPLES);
    });

    it("handles a large batch", async function () {
      const values: bigint[] = [];
      for (let i = 1n; i <= 100n; i++) {
        values.push((i * 0x1234567890abcdefn) % P);
      }
      const result = await harness.invBatch(values);
      for (let i = 0; i < values.length; i++) {
        expect(result[i]).to.equal(modInv(values[i]));
      }
    });

    it("reverts if the first element is zero", async function () {
      await expect(harness.invBatch([0n, 2n, 3n])).to.be.revertedWithCustomError(
        harness,
        "ZeroDivisor",
      );
    });

    it("reverts if a middle element is zero", async function () {
      await expect(harness.invBatch([2n, 0n, 3n])).to.be.revertedWithCustomError(
        harness,
        "ZeroDivisor",
      );
    });

    it("reverts if the last element is zero", async function () {
      await expect(harness.invBatch([2n, 3n, 0n])).to.be.revertedWithCustomError(
        harness,
        "ZeroDivisor",
      );
    });

    it("reverts on a single zero", async function () {
      await expect(harness.invBatch([0n])).to.be.revertedWithCustomError(harness, "ZeroDivisor");
    });
  });
});
