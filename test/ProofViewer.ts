import { expect } from "chai";
import { network } from "hardhat";
import type { ProofViewerHarness } from "../types/ethers-contracts/index.js";
import {
  encodeHeader,
  encodeVarint,
  PLONK_LAYOUT_IDENTIFIER,
  TEST_LAYOUT_IDENTIFIER,
} from "./vectors.js";

const { ethers } = await network.create();

const WORD0 = "0x" + "a0".repeat(32);
const WORD1 = "0x" + "b1".repeat(32);

/** SCPF data whose pool holds `WORD0` and `WORD1`, followed by the given stream. */
function dataWithPool(stream: string) {
  return ethers.concat([encodeHeader(TEST_LAYOUT_IDENTIFIER, 2), WORD0, WORD1, stream]);
}

/** SCPF data with an empty pool, followed by the given stream. */
function dataWithoutPool(stream: string) {
  return ethers.concat([encodeHeader(TEST_LAYOUT_IDENTIFIER, 0), stream]);
}

/** Returns `data` with the byte at `offset` replaced by `value`. */
function withByte(data: string, offset: number, value: number) {
  const bytes = ethers.getBytes(data);
  bytes[offset] = value;
  return ethers.hexlify(bytes);
}

// Same cases as `test_encode_varint` in `starkom_pcs::scpf`.
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
  [(1n << 35n) - 1n, "0xf7ffffffff"],
  [1n << 35n, "0xf80800000000"],
  [(1n << 42n) - 1n, "0xfbffffffffff"],
  [1n << 42n, "0xfc040000000000"],
  [(1n << 49n) - 1n, "0xfdffffffffffff"],
  [1n << 49n, "0xfe02000000000000"],
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
    it("finds the stream after the pool", async function () {
      expect(await harness.open(dataWithPool("0x07"), TEST_LAYOUT_IDENTIFIER)).to.deep.equal([
        2n,
        128n,
      ]);
    });

    it("finds the stream of data without pool", async function () {
      expect(await harness.open(dataWithoutPool("0x07"), TEST_LAYOUT_IDENTIFIER)).to.deep.equal([
        0n,
        64n,
      ]);
    });

    it("accepts an empty stream", async function () {
      expect(await harness.open(dataWithPool("0x"), TEST_LAYOUT_IDENTIFIER)).to.deep.equal([
        2n,
        128n,
      ]);
    });

    it("reads a pool size of more than one byte", async function () {
      const data = ethers.concat([
        encodeHeader(TEST_LAYOUT_IDENTIFIER, 256),
        ...Array(256).fill(WORD0),
      ]);
      expect(await harness.open(data, TEST_LAYOUT_IDENTIFIER)).to.deep.equal([256n, 8256n]);
    });

    for (const version of [
      [1, 1, 2],
      [1, 255, 255],
    ] as [number, number, number][]) {
      it(`accepts version ${version.join(".")}`, async function () {
        const data = encodeHeader(TEST_LAYOUT_IDENTIFIER, 0, version);
        expect(await harness.open(data, TEST_LAYOUT_IDENTIFIER)).to.deep.equal([0n, 64n]);
      });
    }

    for (const major of [0, 2, 10, 255]) {
      it(`rejects major version ${major}`, async function () {
        const data = encodeHeader(TEST_LAYOUT_IDENTIFIER, 0, [major, 0, 0]);
        await expect(harness.open(data, TEST_LAYOUT_IDENTIFIER))
          .to.be.revertedWithCustomError(harness, "UnsupportedVersion")
          .withArgs(major);
      });
    }

    it("rejects another layout", async function () {
      await expect(harness.open(dataWithoutPool("0x"), PLONK_LAYOUT_IDENTIFIER))
        .to.be.revertedWithCustomError(harness, "LayoutMismatch")
        .withArgs(TEST_LAYOUT_IDENTIFIER);
    });

    for (const offset of [0, 3]) {
      it(`rejects a wrong signature (byte ${offset})`, async function () {
        const data = withByte(dataWithoutPool("0x"), offset, 0x20);
        await expect(harness.open(data, TEST_LAYOUT_IDENTIFIER)).to.be.revertedWithCustomError(
          harness,
          "InvalidHeader",
        );
      });
    }

    for (const offset of [4, 7, 11, 15, 52, 63]) {
      it(`rejects a nonzero reserved byte (byte ${offset})`, async function () {
        const data = withByte(dataWithoutPool("0x"), offset, 0x01);
        await expect(harness.open(data, TEST_LAYOUT_IDENTIFIER)).to.be.revertedWithCustomError(
          harness,
          "InvalidHeader",
        );
      });
    }

    it("rejects empty data", async function () {
      await expect(harness.open("0x", TEST_LAYOUT_IDENTIFIER)).to.be.revertedWithCustomError(
        harness,
        "TruncatedProof",
      );
    });

    it("rejects a truncated header", async function () {
      const data = ethers.dataSlice(encodeHeader(TEST_LAYOUT_IDENTIFIER, 0), 0, 63);
      await expect(harness.open(data, TEST_LAYOUT_IDENTIFIER)).to.be.revertedWithCustomError(
        harness,
        "TruncatedProof",
      );
    });

    it("rejects a truncated pool", async function () {
      const data = ethers.concat([
        encodeHeader(TEST_LAYOUT_IDENTIFIER, 2),
        WORD0,
        ethers.dataSlice(WORD1, 1),
      ]);
      await expect(harness.open(data, TEST_LAYOUT_IDENTIFIER)).to.be.revertedWithCustomError(
        harness,
        "TruncatedProof",
      );
    });

    it("rejects the largest pool size", async function () {
      const data = encodeHeader(TEST_LAYOUT_IDENTIFIER, 2 ** 32 - 1);
      await expect(harness.open(data, TEST_LAYOUT_IDENTIFIER)).to.be.revertedWithCustomError(
        harness,
        "TruncatedProof",
      );
    });
  });

  describe("varints", function () {
    for (const [value, bytes] of VARINTS) {
      it(`encodes ${value} as ${bytes}`, async function () {
        expect(encodeVarint(value)).to.equal(bytes);
      });

      it(`decodes ${bytes} as ${value}`, async function () {
        expect(await harness.popVarints(dataWithoutPool(bytes), 1)).to.deep.equal([[value], 0n]);
      });
    }

    it("decodes consecutive varints", async function () {
      const stream = ethers.concat(["0x00", "0x812c", "0xffffffffffffffffff", "0x7f"]);
      expect(await harness.popVarints(dataWithoutPool(stream), 3)).to.deep.equal([
        [0n, 300n, 2n ** 64n - 1n],
        1n,
      ]);
    });

    it("decodes a varint at the end of the calldata", async function () {
      // The varint is read with a 32-byte load that goes past the end of the data.
      expect(await harness.popVarints(dataWithPool("0xc04000"), 1)).to.deep.equal([[16384n], 0n]);
    });

    it("accepts non-minimal encodings", async function () {
      expect(await harness.popVarints(dataWithoutPool("0x8001"), 1)).to.deep.equal([[1n], 0n]);
    });

    it("rejects encodings of more than 64 bits", function () {
      expect(() => encodeVarint(2n ** 64n)).to.throw();
    });
  });

  describe("pool", function () {
    it("returns the words referred to by the stream", async function () {
      expect(await harness.popPoolWords(dataWithPool("0x010001"), 3)).to.deep.equal([
        WORD1,
        WORD0,
        WORD1,
      ]);
    });

    it("rejects an out-of-range reference", async function () {
      await expect(harness.popPoolWords(dataWithPool("0x0102"), 2))
        .to.be.revertedWithCustomError(harness, "InvalidPoolReference")
        .withArgs(2n, 2n);
    });
  });

  describe("inline words", function () {
    it("reads words into an array", async function () {
      const stream = ethers.concat([ethers.toBeHex(12n, 32), ethers.toBeHex(34n, 32)]);
      expect(await harness.popWords(dataWithPool(stream), 2)).to.deep.equal([[12n, 34n], 128n]);
    });

    it("reads no words", async function () {
      expect(await harness.popWords(dataWithPool("0x"), 0)).to.deep.equal([[], 128n]);
    });

    it("skips words", async function () {
      const stream = ethers.concat([ethers.toBeHex(12n, 32), ethers.toBeHex(34n, 32)]);
      expect(await harness.skipWords(dataWithoutPool(stream), 2)).to.equal(64n);
    });
  });

  describe("close", function () {
    it("accepts a stream read to the end", async function () {
      await harness.close(dataWithPool("0x"));
    });

    it("rejects trailing data", async function () {
      await expect(harness.close(dataWithPool("0x0000")))
        .to.be.revertedWithCustomError(harness, "TrailingData")
        .withArgs(2n);
    });

    it("rejects a truncated word", async function () {
      await expect(
        harness.popWords(dataWithPool(ethers.toBeHex(42n, 31)), 1),
      ).to.be.revertedWithCustomError(harness, "TruncatedProof");
    });

    it("rejects a truncated varint", async function () {
      await expect(harness.popPoolWords(dataWithPool("0x00c0"), 2)).to.be.revertedWithCustomError(
        harness,
        "TruncatedProof",
      );
    });
  });
});
