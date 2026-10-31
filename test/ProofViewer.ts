import { expect } from "chai";
import { network } from "hardhat";
import type { ProofViewerHarness } from "../types/ethers-contracts";
import { encodeVarint } from "./vectors";

const { ethers } = await network.create();

const WORD0 = "0x" + "a0".repeat(32);
const WORD1 = "0x" + "b1".repeat(32);

/** A proof whose pool holds `WORD0` and `WORD1`, followed by the given heap. */
function proofWithPool(heap: string) {
  return ethers.concat(["0x02", WORD0, WORD1, heap]);
}

/** A proof with an empty pool, followed by the given heap. */
function proofWithoutPool(heap: string) {
  return ethers.concat(["0x00", heap]);
}

// Same cases as `test_encode_varint` in the `calldata` crate.
const VARINTS: [bigint, string][] = [
  [0n, "0x00"],
  [1n, "0x01"],
  [127n, "0x7f"],
  [128n, "0x8080"],
  [300n, "0x812c"],
  [16383n, "0xbfff"],
  [16384n, "0xc04000"],
  [(1n << 21n) - 1n, "0xdfffff"],
  [1n << 21n, "0xe0200000"],
  [(1n << 28n) - 1n, "0xefffffff"],
  [1n << 28n, "0xf010000000"],
  [(1n << 56n) - 1n, "0xfeffffffffffffff"],
  [1n << 56n, "0xff0100000000000000"],
  [2n ** 64n - 1n, "0xffffffffffffffffff"],
];

describe("ProofViewer", function () {
  let harness: ProofViewerHarness;

  before(async function () {
    harness = await ethers.deployContract("ProofViewerHarness");
  });

  describe("open", function () {
    it("finds the heap after the pool", async function () {
      expect(await harness.open(proofWithPool("0x07"))).to.deep.equal([2n, 65n]);
    });

    it("finds the heap of a proof without pool", async function () {
      expect(await harness.open(proofWithoutPool("0x07"))).to.deep.equal([0n, 1n]);
    });

    it("accepts an empty heap", async function () {
      expect(await harness.open(proofWithPool("0x"))).to.deep.equal([2n, 65n]);
    });

    it("rejects an empty proof", async function () {
      await expect(harness.open("0x")).to.be.revertedWithCustomError(harness, "TruncatedProof");
    });

    it("rejects a truncated pool", async function () {
      await expect(
        harness.open(ethers.concat(["0x02", WORD0, ethers.dataSlice(WORD1, 1)])),
      ).to.be.revertedWithCustomError(harness, "TruncatedProof");
    });
  });

  describe("varints", function () {
    for (const [value, bytes] of VARINTS) {
      it(`encodes ${value} as ${bytes}`, async function () {
        expect(encodeVarint(value)).to.equal(bytes);
      });

      it(`decodes ${bytes} as ${value}`, async function () {
        expect(await harness.popVarints(proofWithoutPool(bytes), 1)).to.deep.equal([[value], 0n]);
      });
    }

    it("decodes consecutive varints", async function () {
      const heap = ethers.concat(["0x00", "0x812c", "0xffffffffffffffffff", "0x7f"]);
      expect(await harness.popVarints(proofWithoutPool(heap), 3)).to.deep.equal([
        [0n, 300n, 2n ** 64n - 1n],
        1n,
      ]);
    });

    it("decodes a varint at the end of the calldata", async function () {
      // The varint is read with a 32-byte load that goes past the end of the proof.
      expect(await harness.popVarints(proofWithPool("0xc04000"), 1)).to.deep.equal([[16384n], 0n]);
    });

    it("accepts non-minimal encodings", async function () {
      expect(await harness.popVarints(proofWithoutPool("0x8001"), 1)).to.deep.equal([[1n], 0n]);
    });

    it("rejects encodings of more than 64 bits", function () {
      expect(() => encodeVarint(2n ** 64n)).to.throw();
    });
  });

  describe("pool", function () {
    it("returns the first word", async function () {
      expect(await harness.poolWord(proofWithPool("0x"), 0)).to.equal(WORD0);
    });

    it("returns the last word", async function () {
      expect(await harness.poolWord(proofWithPool("0x"), 1)).to.equal(WORD1);
    });

    it("rejects an out-of-range index", async function () {
      await expect(harness.poolWord(proofWithPool("0x"), 2))
        .to.be.revertedWithCustomError(harness, "InvalidPoolIndex")
        .withArgs(2n, 2n);
    });

    it("returns the words referred to by the heap", async function () {
      expect(await harness.popPoolWords(proofWithPool("0x010001"), 3)).to.deep.equal([
        WORD1,
        WORD0,
        WORD1,
      ]);
    });

    it("rejects an out-of-range reference", async function () {
      await expect(harness.popPoolWords(proofWithPool("0x0102"), 2))
        .to.be.revertedWithCustomError(harness, "InvalidPoolIndex")
        .withArgs(2n, 2n);
    });
  });

  describe("inline words", function () {
    it("reads a word after a varint", async function () {
      const heap = ethers.concat(["0x05", ethers.toBeHex(42n, 32)]);
      expect(await harness.popVarintAndWord(proofWithPool(heap))).to.deep.equal([5n, 42n]);
    });

    it("reads words into an array", async function () {
      const heap = ethers.concat([ethers.toBeHex(12n, 32), ethers.toBeHex(34n, 32)]);
      expect(await harness.popWords(proofWithPool(heap), 2)).to.deep.equal([[12n, 34n], 65n]);
    });

    it("reads no words", async function () {
      expect(await harness.popWords(proofWithPool("0x"), 0)).to.deep.equal([[], 65n]);
    });

    it("skips words", async function () {
      const heap = ethers.concat([ethers.toBeHex(12n, 32), ethers.toBeHex(34n, 32)]);
      expect(await harness.skipWords(proofWithoutPool(heap), 2)).to.equal(1n);
    });
  });

  describe("close", function () {
    it("accepts a heap read to the end", async function () {
      await harness.close(proofWithPool("0x"));
    });

    it("rejects trailing data", async function () {
      await expect(harness.close(proofWithPool("0x0000")))
        .to.be.revertedWithCustomError(harness, "TrailingData")
        .withArgs(2n);
    });

    it("rejects a truncated word", async function () {
      const heap = ethers.concat(["0x05", ethers.toBeHex(42n, 31)]);
      await expect(harness.popVarintAndWord(proofWithPool(heap))).to.be.revertedWithCustomError(
        harness,
        "TruncatedProof",
      );
    });

    it("rejects a truncated varint", async function () {
      await expect(harness.popPoolWords(proofWithPool("0x00c0"), 2)).to.be.revertedWithCustomError(
        harness,
        "TruncatedProof",
      );
    });
  });
});
