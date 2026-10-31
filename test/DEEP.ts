import { expect } from "chai";
import { network } from "hardhat";
import type { DeepHarness } from "../types/ethers-contracts";
import {
  type DeepCommitment,
  type DeepOptions,
  type DeepProof,
  encodeDeepProof,
  loadDeepCases,
} from "./vectors";

const { ethers } = await network.create();

const P = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001n;

const POW_DST = "0xd659450ee50ebd3de60604eff7a514c5873b63b66073b1164b1cb61b7b113a51";

const cases = loadDeepCases();

function findCase(name: string) {
  return cases.find((testCase) => testCase.name === name)!;
}

// Same setup as `sample_proof(OPTIONS)` and `sample_proof(GROUND_OPTIONS)` in the
// `starkom_pcs::deep` unit tests.
const sample = findCase("sample");
const ground = findCase("sample with grinding");
const foreign = findCase("foreign");

function sampleCommitment(): DeepCommitment {
  return structuredClone(sample.commitment);
}

function sampleProof(): DeepProof {
  return structuredClone(sample.proof);
}

/** Reference implementation of `DeepVerifier.proofOfWork`. */
function proofOfWork(seed: string, nonce: bigint): bigint {
  return BigInt(
    ethers.solidityPackedKeccak256(
      ["bytes32", "uint128", "bytes32", "uint256"],
      [POW_DST, 2n, seed, nonce],
    ),
  );
}

describe("DEEP verifier", function () {
  let harness: DeepHarness;

  before(async function () {
    harness = await ethers.deployContract("DeepHarness");
  });

  /** Encodes the proof in the calldata format and verifies it. */
  function verify(proof: DeepProof, commitment: DeepCommitment = sampleCommitment()) {
    return harness.verify(commitment, encodeDeepProof(proof));
  }

  /**
   * Returns the smallest nonce greater than `proof.nonce` that satisfies (`valid == true`) or fails
   * (`valid == false`) the proof of work of `proof` against `commitment`.
   */
  async function findNonce(commitment: DeepCommitment, proof: DeepProof, valid: boolean) {
    const seed = await harness.querySeed(
      commitment,
      proof.numPolys,
      proof.points,
      proof.friCommitment,
    );
    const bits = proof.options.grindingBits;
    for (let nonce = proof.nonce + 1n; ; nonce++) {
      const satisfied = proofOfWork(seed, nonce) >> (256n - bits) === 0n;
      if (satisfied === valid) {
        return nonce;
      }
    }
  }

  // From the `starkom_pcs::deep::tests::test_*_dst` tests.
  describe("domain separators", function () {
    it("match the Rust implementation", async function () {
      expect(await harness.domainSeparators()).to.deep.equal([
        "0xbbec7289b9fc3aade75412c031b62a769b205d1d73b29c9a06dbb91943e046bc",
        "0x88209086b178c9f2fb9c2f813cd229e1a2528cb4f5e6cd618710dc9869f14ac5",
        "0x688ae37e5f05871810e7c6777e1c16c55ef4b14f072357586d7a298cefc11368",
        "0xa7f91ddaa061a34288a9146bf5afc157211da6ec200650dd93daa9cb4c5b4808",
        POW_DST,
      ]);
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

  // Same cases as the `starkom_pcs::deep::tests::test_*_options_*satisfy` tests.
  describe("satisfies", function () {
    const expected: DeepOptions = {
      degreeBound: 4096n,
      securityBits: 128n,
      blowupLog2: 6n,
      foldRate: 3n,
      maxRounds: 2n,
      grindingBits: 20n,
    };
    const accepted: [string, Partial<DeepOptions>][] = [
      ["equal options", {}],
      ["more grinding bits", { grindingBits: 21n }],
      ["full grinding", { grindingBits: 256n }],
      ["a higher security level", { securityBits: 256n }],
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
      [
        "a higher security level with fewer grinding bits",
        { securityBits: 256n, grindingBits: 19n },
      ],
      ["a smaller degree bound", { degreeBound: 2048n }],
      ["a larger degree bound", { degreeBound: 8192n }],
      ["a smaller blowup factor", { blowupLog2: 5n }],
      ["a larger blowup factor", { blowupLog2: 7n }],
      ["a lower fold rate", { foldRate: 2n }],
      ["a higher fold rate", { foldRate: 4n }],
      ["fewer rounds", { maxRounds: 1n }],
      ["more rounds", { maxRounds: 3n }],
      ["a larger degree bound with more grinding bits", { degreeBound: 8192n, grindingBits: 21n }],
      [
        "a larger degree bound with a higher security level",
        { degreeBound: 8192n, securityBits: 256n },
      ],
    ];
    for (const [name, changes] of rejected) {
      it(`rejects ${name}`, async function () {
        expect(await harness.satisfies({ ...expected, ...changes }, expected)).to.equal(false);
      });
    }
  });

  describe("proof of work", function () {
    // From `starkom_pcs::deep::tests::test_proof_of_work_keccak256`.
    it("matches the Rust implementation", async function () {
      expect(await harness.proofOfWork("0x" + "12".repeat(32), 34n)).to.equal(
        "0x4bd47978101f127ba6b5f99dff54c6110e351615a65e4f8a9fbfc9003ceaa5ec",
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

  describe("encodes proofs like the Rust implementation", function () {
    for (const { name, proof, calldata } of cases) {
      it(name, function () {
        expect(encodeDeepProof(proof)).to.equal(calldata);
      });
    }
  });

  describe("accepts honest proofs", function () {
    for (const { name, commitment, proof, calldata } of cases) {
      const { degreeBound, securityBits, blowupLog2, foldRate, maxRounds, grindingBits } =
        proof.options;
      const description =
        `${name} (degree bound ${degreeBound}, ${securityBits} security bits, ` +
        `blowup 2^${blowupLog2}, fold rate ${foldRate}, ` +
        `max rounds ${maxRounds === 2n ** 64n - 1n ? "unlimited" : maxRounds}, ` +
        `${grindingBits} grinding bits, ${commitment.batches.length} batches, ` +
        `${proof.points.length} points, ${proof.queries.length} queries)`;
      it(description, async function () {
        await harness.verify(commitment, calldata);
      });
    }

    it("returns the parameters and the opened points", async function () {
      const [options, points] = await harness.verify(sample.commitment, sample.calldata);
      const { degreeBound, securityBits, blowupLog2, foldRate, maxRounds, grindingBits } =
        sample.proof.options;
      expect(options).to.deep.equal([
        degreeBound,
        securityBits,
        blowupLog2,
        foldRate,
        maxRounds,
        grindingBits,
      ]);
      expect(points).to.deep.equal(sample.proof.points.map(({ z, values }) => [z, values]));
    });
  });

  // Mirrors the rejection tests in `starkom_pcs::deep::tests`.
  describe("rejects invalid proofs like the Rust implementation", function () {
    it("accepts the untampered proof", async function () {
      await verify(sampleProof());
    });

    it("rejects mismatched max rounds", async function () {
      const proof = sampleProof();
      proof.options.maxRounds = 1n;
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects a mismatched fold rate", async function () {
      const proof = sampleProof();
      proof.options.foldRate = 2n;
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects a mismatched degree bound", async function () {
      const proof = sampleProof();
      proof.options.degreeBound *= 2n;
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects a point in the evaluation domain", async function () {
      // The first element of the shifted domain is the multiplicative generator, 5.
      const proof = sampleProof();
      proof.points = [{ z: 5n, values: proof.points[0].values }];
      await expect(verify(proof))
        .to.be.revertedWithCustomError(harness, "PointInDomain")
        .withArgs(5n);
    });

    it("rejects a tampered evaluation", async function () {
      const proof = sampleProof();
      proof.points[0].values[0] = (proof.points[0].values[0] + 1n) % P;
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects a proof without points", async function () {
      const proof = sampleProof();
      proof.points = [];
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "NoPoints");
    });

    it("rejects a missing evaluation", async function () {
      const proof = sampleProof();
      proof.points[0].values.pop();
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects an extra evaluation", async function () {
      const proof = sampleProof();
      proof.points[0].values.push(0n);
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects an extra point", async function () {
      const proof = sampleProof();
      proof.points.push({ z: 789n, values: [...proof.points[0].values] });
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects swapped evaluations", async function () {
      const proof = sampleProof();
      [proof.points[0].values, proof.points[1].values] = [
        proof.points[1].values,
        proof.points[0].values,
      ];
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects a foreign commitment", async function () {
      await expect(verify(sampleProof(), structuredClone(foreign.commitment))).to.revert(ethers);
    });

    it("rejects misreported batch sizes", async function () {
      const commitment = sampleCommitment();
      commitment.batches[0].numPolys = 1n;
      commitment.batches[1].numPolys = 2n;
      await expect(verify(sampleProof(), commitment)).to.revert(ethers);
    });

    it("rejects the wrong number of polynomials", async function () {
      const proof = sampleProof();
      proof.numPolys += 1n;
      await expect(verify(proof))
        .to.be.revertedWithCustomError(harness, "InvalidNumberOfPolynomials")
        .withArgs(4n, 3n);
    });

    it("rejects a missing query", async function () {
      const proof = sampleProof();
      proof.queries.pop();
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects missing openings", async function () {
      const proof = sampleProof();
      proof.openings.pop();
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects a missing opening within a query", async function () {
      const proof = sampleProof();
      proof.openings[0].proofs.pop();
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects swapped openings", async function () {
      const proof = sampleProof();
      [proof.openings[0], proof.openings[1]] = [proof.openings[1], proof.openings[0]];
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects an opening from the wrong domain", async function () {
      const proof = sampleProof();
      const other = findCase("blowup 8").proof;
      proof.openings[0].proofs[0] = structuredClone(other.openings[0].proofs[0]);
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects an invalid nonce", async function () {
      const commitment = structuredClone(ground.commitment);
      const proof = structuredClone(ground.proof);
      proof.nonce = await findNonce(commitment, proof, false);
      await expect(verify(proof, commitment)).to.be.revertedWithCustomError(
        harness,
        "InsufficientProofOfWork",
      );
    });

    it("rejects another valid nonce", async function () {
      const commitment = structuredClone(ground.commitment);
      const proof = structuredClone(ground.proof);
      proof.nonce = await findNonce(commitment, proof, true);
      await expect(verify(proof, commitment)).to.revert(ethers);
    });

    it("rejects overstated grinding", async function () {
      const proof = structuredClone(ground.proof);
      proof.options.grindingBits = 127n;
      await expect(verify(proof, structuredClone(ground.commitment))).to.be.revertedWithCustomError(
        harness,
        "InsufficientProofOfWork",
      );
    });

    it("rejects an overstated security level", async function () {
      const proof = sampleProof();
      proof.options.securityBits = 130n;
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects an understated security level", async function () {
      const proof = sampleProof();
      proof.options.securityBits = 126n;
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "TrailingData");
    });

    it("rejects a huge security level", async function () {
      const proof = sampleProof();
      // The largest value of a varint, which would mean 2^63 queries.
      proof.options.securityBits = 2n ** 64n - 1n;
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects understated grinding", async function () {
      const proof = structuredClone(ground.proof);
      proof.options.grindingBits = 0n;
      await expect(verify(proof, structuredClone(ground.commitment))).to.revert(ethers);
    });

    it("rejects a tampered folded quotient without rounds", async function () {
      const testCase = findCase("zero rounds");
      const proof = structuredClone(testCase.proof);
      proof.friCommitment.foldedPolynomial[1] = (proof.friCommitment.foldedPolynomial[1] + 1n) % P;
      await expect(verify(proof, structuredClone(testCase.commitment))).to.revert(ethers);
    });

    it("rejects a tampered FRI root", async function () {
      const proof = sampleProof();
      proof.friCommitment.roots[1] = "0x" + "42".repeat(32);
      await expect(verify(proof)).to.revert(ethers);
    });
  });

  // Checks performed by `Options::validate`, `Commitment::from_proto`, and `Proof::from_proto`.
  describe("rejects malformed proofs like `from_proto`", function () {
    it("rejects a zero degree bound", async function () {
      const proof = sampleProof();
      proof.options.degreeBound = 0n;
      await expect(verify(proof))
        .to.be.revertedWithCustomError(harness, "InvalidDegreeBound")
        .withArgs(0n);
    });

    it("rejects a zero fold rate", async function () {
      const proof = sampleProof();
      proof.options.foldRate = 0n;
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "InvalidFoldRate");
    });

    it("rejects a zero blowup factor", async function () {
      const proof = sampleProof();
      proof.options.blowupLog2 = 0n;
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "InvalidBlowupFactor");
    });

    it("rejects an oversized domain", async function () {
      const proof = sampleProof();
      proof.options.blowupLog2 = 64n;
      await expect(verify(proof))
        .to.be.revertedWithCustomError(harness, "DomainTooLarge")
        .withArgs(2n, 64n);
    });

    it("rejects a huge blowup factor without overflowing", async function () {
      const proof = sampleProof();
      // The largest value of a varint.
      proof.options.blowupLog2 = 2n ** 64n - 1n;
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "DomainTooLarge");
    });

    it("rejects unsatisfiable grinding", async function () {
      const proof = structuredClone(ground.proof);
      proof.options.grindingBits = 257n;
      await expect(verify(proof, structuredClone(ground.commitment)))
        .to.be.revertedWithCustomError(harness, "InvalidGrindingBits")
        .withArgs(257n);
    });

    it("rejects the maximum number of grinding bits", async function () {
      const proof = structuredClone(ground.proof);
      // The largest value of a varint.
      proof.options.grindingBits = 2n ** 64n - 1n;
      await expect(verify(proof, structuredClone(ground.commitment)))
        .to.be.revertedWithCustomError(harness, "InvalidGrindingBits")
        .withArgs(2n ** 64n - 1n);
    });

    it("rejects a commitment without batches", async function () {
      await expect(verify(sampleProof(), { batches: [] })).to.be.revertedWithCustomError(
        harness,
        "NoBatches",
      );
    });

    it("rejects a non-canonical point", async function () {
      const proof = sampleProof();
      proof.points[0].z += P;
      await expect(verify(proof))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(proof.points[0].z);
    });

    it("rejects a non-canonical evaluation", async function () {
      const proof = sampleProof();
      proof.points[1].values[2] += P;
      await expect(verify(proof))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(proof.points[1].values[2]);
    });

    it("rejects a non-canonical coefficient of the folded quotient", async function () {
      const proof = sampleProof();
      proof.friCommitment.foldedPolynomial[0] += P;
      await expect(verify(proof))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(proof.friCommitment.foldedPolynomial[0]);
    });

    it("rejects a non-canonical leaf value", async function () {
      const proof = sampleProof();
      proof.openings[3].proofs[1].leaf[0] += P;
      await expect(verify(proof))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(proof.openings[3].proofs[1].leaf[0]);
    });

    it("rejects unsorted points", async function () {
      const proof = sampleProof();
      proof.points.reverse();
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "UnsortedPoints");
    });

    it("rejects duplicate points", async function () {
      const proof = sampleProof();
      proof.points[1] = structuredClone(proof.points[0]);
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "UnsortedPoints");
    });
  });

  describe("rejects malformed calldata", function () {
    it("rejects trailing data", async function () {
      await expect(harness.verify(sampleCommitment(), ethers.concat([sample.calldata, "0x00"])))
        .to.be.revertedWithCustomError(harness, "TrailingData")
        .withArgs(1n);
    });

    it("rejects a truncated proof", async function () {
      const calldata = ethers.dataSlice(sample.calldata, 0, ethers.dataLength(sample.calldata) - 1);
      await expect(harness.verify(sampleCommitment(), calldata)).to.revert(ethers);
    });

    it("rejects an empty proof", async function () {
      await expect(harness.verify(sampleCommitment(), "0x")).to.be.revertedWithCustomError(
        harness,
        "TruncatedProof",
      );
    });
  });

  describe("rejects other tampering", function () {
    it("rejects a tampered leaf value", async function () {
      const proof = sampleProof();
      const leaf = proof.openings[5].proofs[0].leaf;
      leaf[1] = (leaf[1] + 1n) % P;
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects an oversized opening path", async function () {
      // `Proof::verify` in Rust compares `1 << path.len()` with the domain size, which overflows
      // for paths of 64 or more hashes.
      const proof = sampleProof();
      for (let i = 0; i < 64; i++) {
        proof.openings[0].proofs[0].path.push(ethers.ZeroHash);
      }
      await expect(verify(proof)).to.revert(ethers);
    });

    it("rejects a FRI opening inconsistent with the DEEP quotient", async function () {
      // Every value of the first FRI coset is changed, so whatever its position the queried value
      // no longer matches the DEEP quotient computed from the openings.
      const proof = sampleProof();
      const coset = proof.queries[0].folds[0].coset;
      for (let i = 0; i < coset.length; i++) {
        coset[i] = (coset[i] + 1n) % P;
      }
      await expect(verify(proof)).to.be.revertedWithCustomError(harness, "LeafValueMismatch");
    });

    it("rejects a non-canonical FRI coset value", async function () {
      const proof = sampleProof();
      proof.queries[2].folds[1].coset[0] += P;
      await expect(verify(proof))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(proof.queries[2].folds[1].coset[0]);
    });
  });
});
