import { expect } from "chai";
import { network } from "hardhat";
import type { MerkleHarness } from "../types/ethers-contracts";
import { loadFriCases } from "./vectors";

const { ethers } = await network.create();

const P = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001n;

const LEAF_DST = 0x08cb2652a56289bd316cfcb356f5d2be485538e04a601fb14fc2c98f03077fcbn;

const cases = loadFriCases();

/** Reference implementation of `Merkle.hashLeaf`. */
function hashLeaf(values: bigint[]): string {
  return ethers.solidityPackedKeccak256(
    ["uint256", "uint256", "uint256[]"],
    [LEAF_DST, values.length, values]
  );
}

/** Reference implementation of `Keccak256Hash.hashBinary`. */
function hashBinary(left: string, right: string): string {
  return ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [left, right]);
}

/** Builds a Merkle tree on the given leaf hashes, returning all its levels from the leaves up. */
function buildTree(leaves: string[]): string[][] {
  const levels = [leaves];
  while (levels[levels.length - 1].length > 1) {
    const level = levels[levels.length - 1];
    const parents: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      parents.push(hashBinary(level[i], level[i + 1]));
    }
    levels.push(parents);
  }
  return levels;
}

/** Reverses the order of the lowest `numBits` bits of `index`, like `FriVerifier.reverseBits`. */
function reverseBits(index: bigint, numBits: bigint): bigint {
  let result = 0n;
  for (let i = 0n; i < numBits; i++) {
    result = (result << 1n) | (index & 1n);
    index >>= 1n;
  }
  return result;
}

/** Returns the Merkle path of the leaf at `index` in a tree built by `buildTree`. */
function merklePath(levels: string[][], index: number): string[] {
  const path: string[] = [];
  for (const level of levels.slice(0, -1)) {
    path.push(level[index ^ 1]);
    index >>= 1;
  }
  return path;
}

/** A tree with vector leaves, as those of the committed polynomial batches. */
const leaves: bigint[][] = Array.from({ length: 8 }, (_, i) => {
  const i64 = BigInt(i);
  return [i64 * i64 + 7n, P - 1n - i64, 42n];
});
const levels = buildTree(leaves.map(hashLeaf));
const root = levels[levels.length - 1][0];

describe("Merkle", function () {
  let harness: MerkleHarness;

  before(async function () {
    harness = await ethers.deployContract("MerkleHarness");
  });

  describe("LEAF_DST", function () {
    // From `starkom_pcs::merkle::tests::test_dsts`.
    it("matches the Rust implementation", async function () {
      expect(await harness.leafDst()).to.equal(LEAF_DST);
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

    it("agrees with the reference implementation", async function () {
      for (const leaf of [[12n], [34n, 56n], [78n, 90n, 12n], ...leaves]) {
        expect(await harness.hashLeaf(leaf)).to.equal(hashLeaf(leaf));
      }
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
    const index = 3;
    const proof = { leaf: leaves[index], path: merklePath(levels, index) };

    it("accepts every leaf", async function () {
      for (let i = 0; i < leaves.length; i++) {
        await harness.verify({ leaf: leaves[i], path: merklePath(levels, i) }, i, root);
      }
    });

    it("rejects a tampered leaf value", async function () {
      const tampered = structuredClone(proof);
      tampered.leaf[0] = (tampered.leaf[0] + 1n) % P;
      await expect(harness.verify(tampered, index, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a missing leaf value", async function () {
      const tampered = structuredClone(proof);
      tampered.leaf.pop();
      await expect(harness.verify(tampered, index, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a tampered path", async function () {
      const tampered = structuredClone(proof);
      tampered.path[2] = ethers.ZeroHash;
      await expect(harness.verify(tampered, index, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects the wrong root", async function () {
      await expect(harness.verify(proof, index, ethers.ZeroHash)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects the wrong index", async function () {
      await expect(harness.verify(proof, index + 1, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects an index that doesn't fit in the path", async function () {
      await expect(
        harness.verify(proof, index + leaves.length, root)
      ).to.be.revertedWithCustomError(harness, "InvalidIndex");
    });

    it("reports the computed and expected roots", async function () {
      const wrongRoot = ethers.ZeroHash;
      await expect(harness.verify(proof, index, wrongRoot))
        .to.be.revertedWithCustomError(harness, "RootHashMismatch")
        .withArgs(root, wrongRoot);
    });
  });

  // FRI trees have scalar leaves stored as 32-byte big-endian integers in bit-reversed order, so
  // the vectors generated by `starkom-pcs` exercise `verifyPath` on raw leaves.
  describe("verifyPath", function () {
    const honest = cases.find((testCase) => testCase.name === "polynomial of degree 7")!;
    // Query index 3 of a domain of size 32 is stored at position 0b11000.
    const opening = honest.queries[3].folds[0];
    const position = 24;
    const leaf = ethers.toBeHex(opening.value, 32);

    it("accepts every FRI opening of every vector", async function () {
      for (const testCase of cases) {
        for (const query of testCase.queries) {
          const k = testCase.degreeBound.toString(2).length - 1 + Number(testCase.blowupLog2);
          let leafPosition = reverseBits(query.index, BigInt(k));
          for (let round = 0; round < query.folds.length; round++) {
            const { value, path } = query.folds[round];
            const rootHash = testCase.roots[round];
            await harness.verifyPath(ethers.toBeHex(value, 32), path, leafPosition, rootHash);
            leafPosition >>= 1n;
          }
        }
      }
    });

    it("accepts a vector-leaf tree given the leaf hash", async function () {
      await harness.verifyPath(hashLeaf(leaves[5]), merklePath(levels, 5), 5, root);
    });

    it("accepts an empty path when the leaf is the root", async function () {
      await harness.verifyPath(leaf, [], 0, leaf);
    });

    it("accepts a FRI opening at its bit-reversed position", async function () {
      await harness.verifyPath(leaf, opening.path, position, honest.roots[0]);
    });

    it("rejects a FRI opening at its natural position", async function () {
      await expect(
        harness.verifyPath(leaf, opening.path, 3, honest.roots[0])
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects a tampered leaf", async function () {
      const tampered = ethers.toBeHex((opening.value + 1n) % P, 32);
      await expect(
        harness.verifyPath(tampered, opening.path, position, honest.roots[0])
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects the partner's position", async function () {
      await expect(
        harness.verifyPath(leaf, opening.path, position ^ 1, honest.roots[0])
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects an index that doesn't fit in the path", async function () {
      await expect(
        harness.verifyPath(leaf, opening.path, position + 32, honest.roots[0])
      ).to.be.revertedWithCustomError(harness, "InvalidIndex");
    });
  });
});
