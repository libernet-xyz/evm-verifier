import { expect } from "chai";
import { network } from "hardhat";
import type { Keccak256HashHarness } from "../types/ethers-contracts";

const { ethers } = await network.create();

const P = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001n;

/** SHA3-256("starkom/pcs/test"), the DST used by the challenge tests in `starkom_pcs::hash`. */
const TEST_DST = "0x46fced9c25777ff00cbc350056b646bce64bf31b8af5c7cb2c5393f5453ed8e2";

/** Reference implementation of `Hasher::hash_transcript`. */
function hashTranscript(dst: string, transcript: string[]): string {
  return ethers.solidityPackedKeccak256(
    ["bytes32", "uint128", "bytes32[]"],
    [dst, transcript.length, transcript],
  );
}

describe("Keccak256Hash", function () {
  let harness: Keccak256HashHarness;

  before(async function () {
    harness = await ethers.deployContract("Keccak256HashHarness");
  });

  // Test vectors from `starkom_pcs::hash::tests::test_keccak256_hash`.
  describe("hash", function () {
    it("hash([12])", async function () {
      expect(await harness.hash([12n])).to.equal(
        "0xdf6966c971051c3d54ec59162606531493a51404a002842f56009d7e5cf4a8c7",
      );
    });

    it("hash([34, 56])", async function () {
      expect(await harness.hash([34n, 56n])).to.equal(
        "0x72700d0d963d58363ea77095ddabb7ed1a429a1fe618c8ace040205d52391bb9",
      );
    });

    it("hash([78, 90, 12])", async function () {
      expect(await harness.hash([78n, 90n, 12n])).to.equal(
        "0x452eb69ea7065787fb9f51a2894ff6a6ff50ae842aaa68b3ad40ed3580117a8a",
      );
    });

    it("hash([]) is the hash of the empty string", async function () {
      expect(await harness.hash([])).to.equal(ethers.keccak256("0x"));
    });
  });

  // Test vectors from `starkom_pcs::hash::tests::test_keccak256_hash_binary`.
  describe("hashBinary", function () {
    it("first vector", async function () {
      const result = await harness.hashBinary(
        "0x2c8ea861b3ec34715e3d50053d001e9d9929a774954e93ffa1f1784f94339592",
        "0x57c43629d9178a54c611df8562260309677c1a10a3bd3ca4c9997acbc5f908bb",
      );
      expect(result).to.equal("0x0887805e67bb6ece5489f58f1863dffec93f52583cd050eca57c33cbd33abb09");
    });

    it("second vector", async function () {
      const result = await harness.hashBinary(
        "0x229045f7089bd1cb6527f1edd7d94a7e91f2dcf607553e2a89fe24d72b2b013c",
        "0x021905a563d6bf385cb3f2eb4bc69d7750812bcb29542ee4bcfcb0fd0e1bc9b8",
      );
      expect(result).to.equal("0x3cecf97526033fb79c366cde597b0f66b7774ec26388b71fd591d7275c81dfbe");
    });

    it("is not commutative", async function () {
      const left = ethers.keccak256("0x01");
      const right = ethers.keccak256("0x02");
      expect(await harness.hashBinary(left, right)).to.not.equal(
        await harness.hashBinary(right, left),
      );
    });
  });

  describe("hashTranscript", function () {
    const transcripts: string[][] = [
      [],
      ["0x5b584bf4398b7ef509abeb33ba8521c96a4a497ffba046a492cc43ac34174c16"],
      [
        "0x2a1d8bd2a5dc960774c53b77e3e8d677b225bb45ec5d9caaf544e4f229a8afcd",
        "0x39de8bea57c1ab4082270791ce637189f07d169852f8bba5d05784368b505a12",
      ],
    ];

    for (const transcript of transcripts) {
      it(`agrees with the reference for ${transcript.length} element(s)`, async function () {
        expect(await harness.hashTranscript(TEST_DST, transcript)).to.equal(
          hashTranscript(TEST_DST, transcript),
        );
      });
    }
  });

  // Test vectors from `starkom_pcs::hash::tests::test_keccak256_challenge_bluesky`.
  describe("challenge", function () {
    it("one-element transcript", async function () {
      const result = await harness.challenge(TEST_DST, [
        "0x5b584bf4398b7ef509abeb33ba8521c96a4a497ffba046a492cc43ac34174c16",
      ]);
      expect(result).to.equal(0x66647f27ced95c30909f94ab8649419a5457026e3b7d956902401b521672b1bdn);
    });

    it("two-element transcript", async function () {
      const result = await harness.challenge(TEST_DST, [
        "0x2a1d8bd2a5dc960774c53b77e3e8d677b225bb45ec5d9caaf544e4f229a8afcd",
        "0x39de8bea57c1ab4082270791ce637189f07d169852f8bba5d05784368b505a12",
      ]);
      expect(result).to.equal(0x448a77521c4edee2ead1cbaedb7d2b9cdf2f72b7f54abbb6824241ce3f273355n);
    });

    it("three-element transcript", async function () {
      const result = await harness.challenge(TEST_DST, [
        "0x2cbe7a924ef4a68b49dc6eac0fcf7c8504cc9ecfcb1628cf2b9686d8597e088e",
        "0x4f6c036f1eaa65e8b761c7fc972156ca4a8340d47d26cd091c9a63655b415896",
        "0x32c783c083c0fafa4dba39e2176fc3a14791b83d4f1a51372aa483279a93d687",
      ]);
      expect(result).to.equal(0x48e3fc25084ef8f0183b3ed2d827ad8b701a7129c25ba03f471fada5ab59568an);
    });

    it("agrees with the reference (high || low) mod P", async function () {
      const transcript = [ethers.keccak256("0x42")];
      const high = BigInt(hashTranscript(TEST_DST, transcript));
      const low = BigInt(hashTranscript(ethers.toBeHex(BigInt(TEST_DST) + 1n, 32), transcript));
      expect(await harness.challenge(TEST_DST, transcript)).to.equal(((high << 256n) + low) % P);
    });

    it("reverts when dst + 1 overflows", async function () {
      const dst = ethers.toBeHex(ethers.MaxUint256, 32);
      await expect(harness.challenge(dst, [])).to.be.revertedWithPanic(0x11);
    });
  });
});
