import { expect } from "chai";
import { network } from "hardhat";
import type { MerkleHarness } from "../types/ethers-contracts";
import { encodeMerklePath, loadFriCases } from "./vectors";

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

/** Returns the root of the Merkle subtree whose leaves are the given FRI coset values. */
function cosetRoot(coset: bigint[]): string {
  const levels = buildTree(coset.map((value) => ethers.toBeHex(value, 32)));
  return levels[levels.length - 1][0];
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

  /** Verifies a Merkle proof, passing the path in the calldata format. */
  function verify(
    proof: { leaf: bigint[]; path: string[] },
    index: number,
    rootHash: string,
    height: number = proof.path.length
  ) {
    return harness.verify(proof.leaf, encodeMerklePath(proof.path), height, index, rootHash);
  }

  /** Verifies a Merkle path, passing it in the calldata format. */
  function verifyPath(leaf: string, path: string[], index: bigint | number, rootHash: string) {
    return harness.verifyPath(leaf, encodeMerklePath(path), path.length, index, rootHash);
  }

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

  describe("verify", function () {
    const index = 3;
    const proof = { leaf: leaves[index], path: merklePath(levels, index) };

    it("accepts every leaf", async function () {
      for (let i = 0; i < leaves.length; i++) {
        await verify({ leaf: leaves[i], path: merklePath(levels, i) }, i, root);
      }
    });

    it("rejects a tampered leaf value", async function () {
      const tampered = structuredClone(proof);
      tampered.leaf[0] = (tampered.leaf[0] + 1n) % P;
      await expect(verify(tampered, index, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a missing leaf value", async function () {
      const tampered = structuredClone(proof);
      tampered.leaf.pop();
      await expect(verify(tampered, index, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a tampered path", async function () {
      const tampered = structuredClone(proof);
      tampered.path[2] = ethers.ZeroHash;
      await expect(verify(tampered, index, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects the wrong root", async function () {
      await expect(verify(proof, index, ethers.ZeroHash)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects the wrong index", async function () {
      await expect(verify(proof, index + 1, root)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects an index that doesn't fit in the path", async function () {
      await expect(verify(proof, index + leaves.length, root)).to.be.revertedWithCustomError(
        harness,
        "InvalidIndex"
      );
    });

    it("rejects a path shorter than the tree", async function () {
      await expect(verify(proof, index, root, proof.path.length + 1)).to.revert(ethers);
    });

    it("rejects a path longer than the tree", async function () {
      const path = encodeMerklePath([...proof.path, ethers.ZeroHash]);
      await expect(harness.verify(proof.leaf, path, proof.path.length, index, root))
        .to.be.revertedWithCustomError(harness, "TrailingData")
        .withArgs(1n);
    });

    it("reports the computed and expected roots", async function () {
      const wrongRoot = ethers.ZeroHash;
      await expect(verify(proof, index, wrongRoot))
        .to.be.revertedWithCustomError(harness, "RootHashMismatch")
        .withArgs(root, wrongRoot);
    });
  });

  // FRI trees have scalar leaves stored as 32-byte big-endian integers in bit-reversed order, so
  // the vectors generated by `starkom-pcs` exercise `verifyPath` on the roots of the opened cosets.
  describe("verifyPath", function () {
    const honest = cases.find((testCase) => testCase.name === "polynomial of degree 7")!;
    // Query index 3 of a domain of size 32 is stored at position 0b11000, so its pair is the
    // subtree at position 0b1100 one level up.
    const opening = honest.queries[3].folds[0];
    const position = 12;
    const pairRoot = hashBinary(
      ethers.toBeHex(opening.coset[0], 32),
      ethers.toBeHex(opening.coset[1], 32)
    );

    it("accepts every FRI opening of every vector", async function () {
      for (const { options, commitment, queries } of cases) {
        const k = BigInt(options.degreeBound.toString(2).length - 1) + options.blowupLog2;
        for (const query of queries) {
          let cosetPosition = reverseBits(query.index, k) >> options.foldRate;
          for (let round = 0; round < query.folds.length; round++) {
            const { coset, path } = query.folds[round];
            await verifyPath(cosetRoot(coset), path, cosetPosition, commitment.roots[round]);
            cosetPosition >>= options.foldRate;
          }
        }
      }
    });

    it("accepts a vector-leaf tree given the leaf hash", async function () {
      await verifyPath(hashLeaf(leaves[5]), merklePath(levels, 5), 5, root);
    });

    it("accepts an empty path when the leaf is the root", async function () {
      await verifyPath(pairRoot, [], 0, pairRoot);
    });

    it("accepts a FRI pair at its bit-reversed position", async function () {
      await verifyPath(pairRoot, opening.path, position, honest.commitment.roots[0]);
    });

    it("rejects a FRI pair at its natural position", async function () {
      await expect(
        verifyPath(pairRoot, opening.path, 1, honest.commitment.roots[0])
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects a tampered pair", async function () {
      const tampered = hashBinary(
        ethers.toBeHex((opening.coset[0] + 1n) % P, 32),
        ethers.toBeHex(opening.coset[1], 32)
      );
      await expect(
        verifyPath(tampered, opening.path, position, honest.commitment.roots[0])
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects a swapped pair", async function () {
      const swapped = hashBinary(
        ethers.toBeHex(opening.coset[1], 32),
        ethers.toBeHex(opening.coset[0], 32)
      );
      await expect(
        verifyPath(swapped, opening.path, position, honest.commitment.roots[0])
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects an index that doesn't fit in the path", async function () {
      await expect(
        verifyPath(pairRoot, opening.path, position + 16, honest.commitment.roots[0])
      ).to.be.revertedWithCustomError(harness, "InvalidIndex");
    });
  });
});
