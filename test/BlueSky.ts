import { expect } from "chai";
import { network } from "hardhat";
import type { BlueSkyHarness } from "../types/ethers-contracts";

const { ethers } = await network.create();

const P = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001n;

const TWO_INV =
  0x3fffffffffffffffffffffffffffffff0339eef94f4daaa3e000000000000001n;

const ROOT_OF_UNITY =
  0x2772569d549e1249ca6891eceba43568f6e0a747a2afe898b3977ca1a5bbfc9cn;

const ROOT_OF_UNITY_INV =
  0x76def406f046ef5ee7eeecd2c4e6ecd7cdedc4e2bcf6b19f1420121cd00b4cdbn;

describe("BlueSky field arithmetic", function () {
  let harness: BlueSkyHarness;

  before(async function () {
    harness = await ethers.deployContract("BlueSkyHarness");
  });

  describe("constants", function () {
    it("TWO_INV * 2 = 1", async function () {
      const result = await harness.mul(TWO_INV, 2n);
      expect(result).to.equal(1n);
    });

    it("ROOT_OF_UNITY^(2^62) = 1 (order divides 2^62)", async function () {
      const result = await harness.pow(ROOT_OF_UNITY, 2n ** 62n);
      expect(result).to.equal(1n);
    });

    it("ROOT_OF_UNITY^(2^61) != 1 (primitive, order is exactly 2^62)", async function () {
      const result = await harness.pow(ROOT_OF_UNITY, 2n ** 61n);
      expect(result).to.not.equal(1n);
    });

    it("ROOT_OF_UNITY * ROOT_OF_UNITY_INV = 1", async function () {
      const result = await harness.mul(ROOT_OF_UNITY, ROOT_OF_UNITY_INV);
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
      await expect(harness.inv(0n)).to.be.revertedWith("zero");
    });
  });
});
