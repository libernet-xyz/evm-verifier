import { expect } from "chai";
import { network } from "hardhat";
import type { DeepHarness } from "../types/ethers-contracts/index.js";
import type {
  DeepCommitment,
  DeepOptions,
  DeepPoint,
  FriCommitment,
  FriOptions,
} from "./vectors.js";

const { ethers } = await network.create();

const POW_DST = "0xd659450ee50ebd3de60604eff7a514c5873b63b66073b1164b1cb61b7b113a51";

// The DEEP-FRI verification itself is tested through the PLONK verifier (see `PLONK.ts`), whose
// proofs embed DEEP-FRI proofs. These tests cover the helpers of `DeepVerifier`.

/** Arbitrary inputs of the transcript: two batches, one of them over the base field. */
const options: DeepOptions = {
  degreeBound: 4n,
  securityBits: 128n,
  blowupLog2: 4n,
  grindingBits: 0n,
};
const friOptions: FriOptions = {
  degreeBound: 4n,
  blowupLog2: 4n,
  foldRate: 1n,
  maxRounds: 2n ** 32n - 1n,
};
const commitment: DeepCommitment = {
  batches: [
    { baseField: true, numPolys: 2n, root: "0x" + "11".repeat(32) },
    { baseField: false, numPolys: 1n, root: "0x" + "22".repeat(32) },
  ],
};
const numPolys = 3n;
const points: DeepPoint[] = [
  { z: 123n, values: [1n, 2n, 3n] },
  { z: 456n, values: [4n, 5n, 6n] },
];
const friCommitment: FriCommitment = {
  roots: ["0x" + "33".repeat(32), "0x" + "44".repeat(32)],
  foldedPolynomial: [7n],
};

/** Reference implementation of `DeepVerifier.proofOfWork`. */
function proofOfWork(seed: string, nonce: bigint): bigint {
  return BigInt(
    ethers.solidityPackedKeccak256(
      ["bytes32", "uint256", "bytes32", "uint256"],
      [POW_DST, 2n, seed, nonce],
    ),
  );
}

describe("DEEP verifier", function () {
  let harness: DeepHarness;

  before(async function () {
    harness = await ethers.deployContract("DeepHarness");
  });

  // From the `starkom_pcs::deep::tests::test_*_dst` tests.
  describe("domain separators", function () {
    it("match the Rust implementation", async function () {
      expect(await harness.domainSeparators()).to.deep.equal([
        "0x81d5f3b82177662e6bc225147d63ffc9fbc536ce42e554dde965e4e421d0ec8b",
        "0xbbec7289b9fc3aade75412c031b62a769b205d1d73b29c9a06dbb91943e046bc",
        "0x88209086b178c9f2fb9c2f813cd229e1a2528cb4f5e6cd618710dc9869f14ac5",
        "0x688ae37e5f05871810e7c6777e1c16c55ef4b14f072357586d7a298cefc11368",
        "0xa7f91ddaa061a34288a9146bf5afc157211da6ec200650dd93daa9cb4c5b4808",
        POW_DST,
      ]);
    });
  });

  // From `starkom_pcs::MAX_FRI_ROUNDS`.
  describe("MAX_FRI_ROUNDS", function () {
    it("matches the Rust implementation", async function () {
      expect(await harness.maxFriRounds()).to.equal(2n ** 32n - 1n);
    });
  });

  // Same cases as `starkom_pcs::deep::tests::test_num_queries_*`, plus security levels that would
  // overflow a plain `(bits + blowupLog2 - 1) / blowupLog2`.
  describe("numQueries", function () {
    const cases: [bigint, bigint, bigint, bigint][] = [
      [128n, 1n, 0n, 128n],
      [128n, 4n, 0n, 32n],
      [128n, 6n, 0n, 22n],
      [128n, 4n, 1n, 32n],
      [128n, 4n, 4n, 31n],
      [128n, 4n, 20n, 27n],
      [128n, 6n, 20n, 18n],
      [128n, 4n, 128n, 1n],
      [128n, 4n, 256n, 1n],
      [128n, 4n, 257n, 1n],
      [128n, 4n, ethers.MaxUint256, 1n],
      [0n, 4n, 0n, 1n],
      [1n, 4n, 0n, 1n],
      [64n, 4n, 0n, 16n],
      [96n, 1n, 26n, 70n],
      [100n, 3n, 0n, 34n],
      [256n, 4n, 0n, 64n],
      [256n, 4n, 20n, 59n],
      [256n, 8n, 20n, 30n],
      [256n, 4n, 250n, 2n],
      [256n, 4n, 256n, 1n],
      [ethers.MaxUint256, 1n, 0n, ethers.MaxUint256],
      [ethers.MaxUint256, 4n, 0n, 2n ** 254n],
    ];
    for (const [securityBits, blowupLog2, grindingBits, expected] of cases) {
      const name = `numQueries(${securityBits}, ${blowupLog2}, ${grindingBits}) = ${expected}`;
      it(name, async function () {
        expect(await harness.numQueries(securityBits, blowupLog2, grindingBits)).to.equal(expected);
      });
    }
  });

  // The cases of the `starkom_pcs::deep::tests::test_*_options_*satisfy` tests that don't change
  // the FRI settings, which `DeepOptions` doesn't have.
  describe("satisfies", function () {
    const expected: DeepOptions = {
      degreeBound: 4096n,
      securityBits: 128n,
      blowupLog2: 6n,
      grindingBits: 20n,
    };
    const accepted: [string, Partial<DeepOptions>][] = [
      ["equal options", {}],
      ["more grinding bits", { grindingBits: 21n }],
      ["full grinding", { grindingBits: 256n }],
    ];
    for (const [name, changes] of accepted) {
      it(`accepts ${name}`, async function () {
        expect(await harness.satisfies({ ...expected, ...changes }, expected)).to.equal(true);
      });
    }
    const rejected: [string, Partial<DeepOptions>][] = [
      ["fewer grinding bits", { grindingBits: 19n }],
      ["no grinding", { grindingBits: 0n }],
      ["a lower security level", { securityBits: 127n }],
      ["a higher security level", { securityBits: 256n }],
      [
        "a higher security level with more grinding bits",
        { securityBits: 256n, grindingBits: 21n },
      ],
      ["a smaller degree bound", { degreeBound: 2048n }],
      ["a larger degree bound", { degreeBound: 8192n }],
      ["a smaller blowup factor", { blowupLog2: 5n }],
      ["a larger blowup factor", { blowupLog2: 7n }],
      ["a larger degree bound with more grinding bits", { degreeBound: 8192n, grindingBits: 21n }],
    ];
    for (const [name, changes] of rejected) {
      it(`rejects ${name}`, async function () {
        expect(await harness.satisfies({ ...expected, ...changes }, expected)).to.equal(false);
      });
    }
  });

  // Mirrors `starkom_pcs::deep::tests::test_deep_transcript_hash_binds_options`, checking that the
  // parameters reach both the DEEP challenges and the query seed through the transcript hash.
  describe("transcript", function () {
    // The changes of the DEEP parameters and of the FRI settings, which share the degree bound and
    // the blowup factor.
    const others: [string, Partial<DeepOptions>, Partial<FriOptions>][] = [
      ["degree bound", { degreeBound: 8n }, { degreeBound: 8n }],
      ["security level", { securityBits: 129n }, {}],
      ["blowup factor", { blowupLog2: 3n }, { blowupLog2: 3n }],
      ["fold rate", {}, { foldRate: 2n }],
      ["maximum number of rounds", {}, { maxRounds: 1n }],
      ["number of grinding bits", { grindingBits: 8n }, {}],
    ];

    it("starts with the parameters", async function () {
      const transcript = await harness.deepTranscript(
        options,
        friOptions,
        commitment,
        numPolys,
        points,
      );
      expect(transcript.slice(0, 7)).to.deep.equal(
        [
          options.degreeBound,
          options.securityBits,
          options.blowupLog2,
          friOptions.foldRate,
          friOptions.maxRounds,
          options.grindingBits,
          BigInt(commitment.batches.length),
        ].map((value) => ethers.toBeHex(value, 32)),
      );
    });

    for (const [name, changes, friChanges] of others) {
      it(`binds the ${name} into the DEEP challenges`, async function () {
        const [alpha, beta] = await harness.deepChallenges(
          options,
          friOptions,
          commitment,
          numPolys,
          points,
        );
        const [otherAlpha, otherBeta] = await harness.deepChallenges(
          { ...options, ...changes },
          { ...friOptions, ...friChanges },
          commitment,
          numPolys,
          points,
        );
        expect(otherAlpha).to.not.equal(alpha);
        expect(otherBeta).to.not.equal(beta);
      });

      it(`binds the ${name} into the query seed`, async function () {
        const seed = await harness.querySeed(
          options,
          friOptions,
          commitment,
          numPolys,
          points,
          friCommitment,
        );
        const otherSeed = await harness.querySeed(
          { ...options, ...changes },
          { ...friOptions, ...friChanges },
          commitment,
          numPolys,
          points,
          friCommitment,
        );
        expect(otherSeed).to.not.equal(seed);
      });
    }
  });

  describe("proof of work", function () {
    // From `starkom_pcs::deep::tests::test_proof_of_work_keccak256`.
    it("matches the Rust implementation", async function () {
      expect(await harness.proofOfWork("0x" + "12".repeat(32), 34n)).to.equal(
        "0xfe341a32d1d3987da41fe4262ae9914dd0ab1f0234dac9ff5b9fbe76b1243ea0",
      );
    });

    it("matches the reference implementation", async function () {
      const seed = "0x" + "34".repeat(32);
      expect(BigInt(await harness.proofOfWork(seed, 56n))).to.equal(proofOfWork(seed, 56n));
    });

    // Same cases as `starkom_pcs::deep::tests::test_check_proof_of_work_*`.
    const cases: [string, bigint, boolean][] = [
      ["0x" + "ff".repeat(32), 0n, true],
      ["0x" + "ff".repeat(32), 1n, false],
      ["0x00001" + "f".repeat(59), 19n, true],
      ["0x00001" + "f".repeat(59), 20n, false],
      [ethers.zeroPadValue("0x01", 32), 255n, true],
      [ethers.zeroPadValue("0x01", 32), 256n, false],
      [ethers.ZeroHash, 256n, true],
      [ethers.ZeroHash, 257n, false],
      [ethers.ZeroHash, ethers.MaxUint256, false],
    ];
    for (const [hash, grindingBits, expected] of cases) {
      const prefix = hash.slice(0, 10);
      it(`checkProofOfWork(${prefix}..., ${grindingBits}) = ${expected}`, async function () {
        expect(await harness.checkProofOfWork(hash, grindingBits)).to.equal(expected);
      });
    }
  });
});
