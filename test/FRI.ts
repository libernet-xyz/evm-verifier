import { expect } from "chai";
import { network } from "hardhat";
import type { FriHarness } from "../types/ethers-contracts";

const { ethers } = await network.create();

const LEAF_DST =
  0x6ade565de4068c14b708c2aeb582b747d8159fd173dd4ecb32ef2d54683e2cfen;
const TREE_DST =
  0x17a4e1d7f96a99904bcf07467db89f654d651724f57c477d41c52418c3aa6783n;
const FOLD_DST =
  0x21e331ad95b69e952c269e82b37c9e470942d5379584f7a0e311481b7ad77942n;

describe("FRI verifier", function () {
  let harness: FriHarness;

  before(async function () {
    harness = await ethers.deployContract("FriHarness");
  });

  describe("hashRaw", function () {
    it("hashRaw(LEAF_DST, 0, 0)", async function () {
      const result = await harness.hashRaw(LEAF_DST, 0n, 0n);
      expect(result).to.equal(
        0x571d3849117e7fafbde7801724e1900c175ccfc708d75f50f02f5c6fafd06fdan,
      );
    });

    it("hashRaw(TREE_DST, 1, 2)", async function () {
      const result = await harness.hashRaw(TREE_DST, 1n, 2n);
      expect(result).to.equal(
        0x6519579ba6f4d6a6649dae10bbca64894738206376f9a458b7ceeb810ec40cc3n,
      );
    });

    it("hashRaw(FOLD_DST, 1, 0)", async function () {
      const result = await harness.hashRaw(FOLD_DST, 1n, 0n);
      expect(result).to.equal(
        0x0e6a745bb7169bc2b785ef55471ffe752491b016e6422122ffb0b217f2b328a5n,
      );
    });
  });

  describe("hashLeaf", function () {
    it("hashLeaf([1])", async function () {
      const result = await harness.hashLeaf([1n]);
      expect(result).to.equal(
        0x18cf5ad5fe14a4dfa6cb167d0ec8102a6c22b1ea58f46ddbbd373fb7c4e78bccn,
      );
    });

    it("hashLeaf([1, 2])", async function () {
      const result = await harness.hashLeaf([1n, 2n]);
      expect(result).to.equal(
        0x6da6b0bc432398d18018395009f515cdb2b4150c31f0f2bd90167eea00900d3bn,
      );
    });

    it("hashLeaf([42])", async function () {
      const result = await harness.hashLeaf([42n]);
      expect(result).to.equal(
        0x4bf291c4bd06923e759bf21f700984c36bc28244293980f936656e823662c834n,
      );
    });
  });

  describe("verifyMerklePath", function () {
    // From the constant polynomial proof (n=2, leaf=[42], sibling=hashLeaf([42])).
    const LEAF_42_HASH =
      0x4bf291c4bd06923e759bf21f700984c36bc28244293980f936656e823662c834n;
    const ROOT_N2 =
      0x035a6f1b94f6137e7e6a553b50225ab1bae5fc2630dfcb27db0220642ebefff2n;

    it("valid left proof at index 0", async function () {
      const result = await harness.verifyMerklePath(
        { leaf: [42n], path: [LEAF_42_HASH] },
        0n,
        ROOT_N2,
      );
      expect(result).to.equal(true);
    });

    it("valid right proof at index 1", async function () {
      const result = await harness.verifyMerklePath(
        { leaf: [42n], path: [LEAF_42_HASH] },
        1n,
        ROOT_N2,
      );
      expect(result).to.equal(true);
    });

    it("wrong leaf value returns false", async function () {
      const result = await harness.verifyMerklePath(
        { leaf: [99n], path: [LEAF_42_HASH] },
        0n,
        ROOT_N2,
      );
      expect(result).to.equal(false);
    });

    it("wrong root returns false", async function () {
      const result = await harness.verifyMerklePath(
        { leaf: [42n], path: [LEAF_42_HASH] },
        0n,
        ROOT_N2 + 1n,
      );
      expect(result).to.equal(false);
    });
  });

  describe("isConstant", function () {
    const LEAF_42_HASH =
      0x4bf291c4bd06923e759bf21f700984c36bc28244293980f936656e823662c834n;

    it("constant leaf returns true", async function () {
      const result = await harness.isConstant({
        leaf: [42n],
        path: [LEAF_42_HASH],
      });
      expect(result).to.equal(true);
    });

    it("non-constant leaf returns false", async function () {
      // Different sibling hash means the partner has a different value.
      const result = await harness.isConstant({
        leaf: [42n],
        path: [LEAF_42_HASH + 1n],
      });
      expect(result).to.equal(false);
    });

    it("empty path is trivially constant", async function () {
      const result = await harness.isConstant({ leaf: [42n], path: [] });
      expect(result).to.equal(true);
    });
  });

  describe("verifyQuery", function () {
    // Test vector 1: constant polynomial f(x)=42, degree_bound=1, blowup=1 => n=2, 1 round.
    it("constant polynomial (n=2, index=0)", async function () {
      const LEAF_42_HASH =
        0x4bf291c4bd06923e759bf21f700984c36bc28244293980f936656e823662c834n;
      await harness.verifyQuery(
        {
          n: 2n,
          index: 0n,
          rounds: [
            {
              left: { leaf: [42n], path: [LEAF_42_HASH] },
              right: { leaf: [42n], path: [LEAF_42_HASH] },
            },
          ],
        },
        {
          roots: [
            0x035a6f1b94f6137e7e6a553b50225ab1bae5fc2630dfcb27db0220642ebefff2n,
          ],
        },
      );
    });

    // Test vector 2: degree-1 polynomial f(x)=1+x, degree_bound=2, blowup=1 => n=4, 2 rounds.
    it("degree-1 polynomial 1+x (n=4, index=0)", async function () {
      await harness.verifyQuery(
        {
          n: 4n,
          index: 0n,
          rounds: [
            {
              left: {
                leaf: [
                  0x0000000000000000000000000000000000000000000000000000000000000006n,
                ],
                path: [
                  0x50a6531d16e3c5e10bd3120ec203ac9aee667d5398a3a33eb0967e027912fcc7n,
                  0x0dda3d045e041a7a31b6b743afd9bcae377ddf8d3a0fe3145762d88abd9e8ba9n,
                ],
              },
              right: {
                leaf: [
                  0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547bffffffffffffffdn,
                ],
                path: [
                  0x0e47bc08330c07d74100e594c2a3582828678dba021860205b5617ee97685c3an,
                  0x6669dde68e81aeab93771ac0f37f8c31bdb07c7833fb4252420d21d233edfe71n,
                ],
              },
            },
            {
              left: {
                leaf: [
                  0x26f4e52b036b62580e44bd56e11740a406496ec3a9b1643ee060015d501216edn,
                ],
                path: [
                  0x3249c79b94d054228a48302249313261ceeb960354045b103573c469c1360cb5n,
                ],
              },
              right: {
                leaf: [
                  0x26f4e52b036b62580e44bd56e11740a406496ec3a9b1643ee060015d501216edn,
                ],
                path: [
                  0x3249c79b94d054228a48302249313261ceeb960354045b103573c469c1360cb5n,
                ],
              },
            },
          ],
        },
        {
          roots: [
            0x43de85c84abd2a4d099e35227ee3c3369b11141ab63a5234bb7bd11cea5bebe7n,
            0x18ded41f57a72da7d64ff3d3628fdbfbf5c573b92b65d24d6d0488e18a80b3a0n,
          ],
        },
      );
    });

    // Test vector 3: two polynomials [1+2x, 3+4x], degree_bound=2, blowup=1 => n=4, index=1.
    it("two polynomials [1+2x, 3+4x] (n=4, index=1)", async function () {
      await harness.verifyQuery(
        {
          n: 4n,
          index: 1n,
          rounds: [
            {
              left: {
                leaf: [
                  0x4fa7b9c7cb2c7e1b38f5285ac3e6bc986c416ce937516a72420d97fb839e6been,
                  0x1f4f738f9658fc3671ea50b587cd7932d20efbdfd0077f9cc41b2ff7073cd7dcn,
                ],
                path: [
                  0x1110bf02d50a47158acdf4e17cb73c56f4575a2a87924a597472c9ee6fa8245en,
                  0x659ef99a2a9001661eebf38dec6757a618a239b11793760a2b2536a21e49cd30n,
                ],
              },
              right: {
                leaf: [
                  0x3058463834d381e4c70ad7a53c1943659a3271096749ead57df268047c619415n,
                  0x60b08c7069a703c98e15af4a783286cb3464e212ce93d5aafbe4d008f8c3282bn,
                ],
                path: [
                  0x4fe0f38a9284483be76b9b11a1dcd95a486b51a9ad83c1711b69dd80fbead4f7n,
                  0x3feca46ce45d8b1d9f26c602a02a1ee2c51d9edd9155ea4f48189356de22562cn,
                ],
              },
            },
            {
              left: {
                leaf: [
                  0x39e49204bc4982eec575f953c3bb62d148e8fea239e8182b2238c0bf7307935en,
                  0x73c92409789305dd8aebf2a78776c5a291d1fd4473d030564471817ee60f26bdn,
                ],
                path: [
                  0x3ee42b10d42af7c0674721209933ff550f5065e7e5b3e613b4b388208375161dn,
                ],
              },
              right: {
                leaf: [
                  0x39e49204bc4982eec575f953c3bb62d148e8fea239e8182b2238c0bf7307935en,
                  0x73c92409789305dd8aebf2a78776c5a291d1fd4473d030564471817ee60f26bdn,
                ],
                path: [
                  0x3ee42b10d42af7c0674721209933ff550f5065e7e5b3e613b4b388208375161dn,
                ],
              },
            },
          ],
        },
        {
          roots: [
            0x72b57ebcc1237ab6a1de42733fccf8d08f2b66ee7dd5247bbf378d10c69b4c65n,
            0x7c8ab83415bda8b11fd5d4e666dfd7ab53eb9595fa0741d9ae0436e5c968c21an,
          ],
        },
      );
    });

    it("rejects tampered leaf value", async function () {
      const LEAF_42_HASH =
        0x4bf291c4bd06923e759bf21f700984c36bc28244293980f936656e823662c834n;
      await expect(
        harness.verifyQuery(
          {
            n: 2n,
            index: 0n,
            rounds: [
              {
                left: { leaf: [43n], path: [LEAF_42_HASH] },
                right: { leaf: [42n], path: [LEAF_42_HASH] },
              },
            ],
          },
          {
            roots: [
              0x035a6f1b94f6137e7e6a553b50225ab1bae5fc2630dfcb27db0220642ebefff2n,
            ],
          },
        ),
      ).to.be.revertedWithCustomError(harness, "InvalidFriQuery");
    });

    it("rejects tampered root hash", async function () {
      const LEAF_42_HASH =
        0x4bf291c4bd06923e759bf21f700984c36bc28244293980f936656e823662c834n;
      await expect(
        harness.verifyQuery(
          {
            n: 2n,
            index: 0n,
            rounds: [
              {
                left: { leaf: [42n], path: [LEAF_42_HASH] },
                right: { leaf: [42n], path: [LEAF_42_HASH] },
              },
            ],
          },
          {
            roots: [
              0x035a6f1b94f6137e7e6a553b50225ab1bae5fc2630dfcb27db0220642ebefff2n +
                1n,
            ],
          },
        ),
      ).to.be.revertedWithCustomError(harness, "InvalidFriQuery");
    });
  });
});
