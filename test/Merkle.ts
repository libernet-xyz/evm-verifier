import { expect } from "chai";
import { network } from "hardhat";
import type { MerkleHarness } from "../types/ethers-contracts";
import { loadFriCases } from "./vectors";

const { ethers } = await network.create();

const P = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001n;

const cases = loadFriCases();

/** The "honest prover" case: one polynomial of degree 7, degree bound 8, blowup factor 4. */
const honest = cases.find((testCase) => testCase.name === "one polynomial of degree 7")!;

describe("Merkle", function () {
  let harness: MerkleHarness;

  before(async function () {
    harness = await ethers.deployContract("MerkleHarness");
  });

  describe("LEAF_DST", function () {
    // From `starkom_pcs::merkle::tests::test_dsts`.
    it("matches the Rust implementation", async function () {
      expect(await harness.leafDst()).to.equal(
        0x08cb2652a56289bd316cfcb356f5d2be485538e04a601fb14fc2c98f03077fcbn
      );
    });
  });

  // Test vectors from `starkom_pcs::merkle::tests::test_hash_leaf_keccak256_bluesky`.
  describe("hashLeaf", function () {
    it("hashLeaf([12])", async function () {
      expect(await harness.hashLeaf([12n])).to.equal(
        "0x5e70242e081756f445b5f3048611464568002e68800238dcfef718504de01782"
      );
    });

    it("hashLeaf([34, 56])", async function () {
      expect(await harness.hashLeaf([34n, 56n])).to.equal(
        "0x6cbf9a3af9793caffe8c509dfaccf0198e833cafa8eb83a0a7d57ce35a97dbd1"
      );
    });

    it("hashLeaf([78, 90, 12])", async function () {
      expect(await harness.hashLeaf([78n, 90n, 12n])).to.equal(
        "0x05ce2ee03a570540c8a67a9b5a419dc7813922da6a39dff3c293806ed0f88fbb"
      );
    });
  });

  describe("validate", function () {
    it("accepts canonical values", async function () {
      await harness.validate({ leaf: [0n, 1n, P - 1n], path: [] });
    });

    it("accepts an empty leaf", async function () {
      await harness.validate({ leaf: [], path: [] });
    });

    it("rejects P", async function () {
      await expect(harness.validate({ leaf: [1n, P], path: [] }))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(P);
    });

    it("rejects 2^256 - 1", async function () {
      await expect(
        harness.validate({ leaf: [ethers.MaxUint256], path: [] })
      ).to.be.revertedWithCustomError(harness, "NonCanonicalScalar");
    });
  });

  describe("verify", function () {
    const query = honest.queries[3];
    const n = 32n;
    const root = honest.roots[0];

    it("accepts every opening of every vector", async function () {
      for (const testCase of cases) {
        const domainSize = testCase.degreeBound << testCase.blowupLog2;
        for (const query of testCase.queries) {
          const index = query.index;
          await harness.verify(query.folds[0].left, index, testCase.roots[0]);
          await harness.verify(
            query.folds[0].right,
            (index + domainSize / 2n) % domainSize,
            testCase.roots[0]
          );
        }
      }
    });

    it("rejects a tampered leaf value", async function () {
      const proof = structuredClone(query.folds[0].left);
      proof.leaf[0] = (proof.leaf[0] + 1n) % P;
      await expect(harness.verify(proof, query.index, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a tampered path", async function () {
      const proof = structuredClone(query.folds[0].left);
      proof.path[2] = ethers.ZeroHash;
      await expect(harness.verify(proof, query.index, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects the wrong root", async function () {
      await expect(
        harness.verify(query.folds[0].left, query.index, honest.roots[1])
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects the wrong index", async function () {
      await expect(
        harness.verify(query.folds[0].left, query.index + 1n, root)
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects an index that doesn't fit in the path", async function () {
      await expect(
        harness.verify(query.folds[0].left, query.index + n, root)
      ).to.be.revertedWithCustomError(harness, "InvalidIndex");
    });

    it("reports the computed and expected roots", async function () {
      const wrongRoot = ethers.ZeroHash;
      const proof = query.folds[0].left;
      // Recompute the root the same way the contract does to check the error arguments.
      let hash = await harness.hashLeaf(proof.leaf);
      let index = query.index;
      for (const sibling of proof.path) {
        hash =
          index & 1n
            ? ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [sibling, hash])
            : ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [hash, sibling]);
        index >>= 1n;
      }
      expect(hash).to.equal(root);
      await expect(harness.verify(proof, query.index, wrongRoot))
        .to.be.revertedWithCustomError(harness, "RootHashMismatch")
        .withArgs(root, wrongRoot);
    });
  });

  describe("isConstant", function () {
    it("is true for the last fold of every vector", async function () {
      for (const testCase of cases) {
        for (const query of testCase.queries) {
          const last = query.folds[query.folds.length - 1];
          expect(await harness.isConstant(last.left)).to.equal(true);
          expect(await harness.isConstant(last.right)).to.equal(true);
        }
      }
    });

    it("is false for the main tree of a non-constant polynomial", async function () {
      expect(await harness.isConstant(honest.queries[0].folds[0].left)).to.equal(false);
    });

    it("is true for an empty path", async function () {
      expect(await harness.isConstant({ leaf: [42n], path: [] })).to.equal(true);
    });

    it("is true when every sibling equals the running hash", async function () {
      const leafHash = await harness.hashLeaf([42n]);
      const parentHash = ethers.solidityPackedKeccak256(
        ["bytes32", "bytes32"],
        [leafHash, leafHash]
      );
      expect(await harness.isConstant({ leaf: [42n], path: [leafHash, parentHash] })).to.equal(
        true
      );
    });

    it("is false when a sibling differs", async function () {
      const leafHash = await harness.hashLeaf([42n]);
      expect(await harness.isConstant({ leaf: [42n], path: [leafHash, leafHash] })).to.equal(false);
    });
  });
});
