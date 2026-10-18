import { expect } from "chai";
import { network } from "hardhat";
import type { FriHarness, Keccak256HashHarness } from "../types/ethers-contracts";
import { type FriQuery, loadFriCases } from "./vectors";

const { ethers } = await network.create();

const P = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001n;

const cases = loadFriCases();

function findCase(name: string) {
  return cases.find((testCase) => testCase.name === name)!;
}

// Same setup as the unit tests in `starkom_pcs::fri`.
const honest = findCase("polynomial of degree 7");
const foreign = findCase("foreign polynomial of degree 7");
const DEGREE_BOUND = 8n;
const BLOWUP_LOG2 = 2n;
const QUERY_INDEX = 3;

function honestQuery(index: number = QUERY_INDEX): FriQuery {
  return structuredClone(honest.queries[index]);
}

function honestCommitment() {
  return { roots: [...honest.roots] };
}

describe("FRI verifier", function () {
  let harness: FriHarness;
  let hashHarness: Keccak256HashHarness;

  before(async function () {
    harness = await ethers.deployContract("FriHarness");
    hashHarness = await ethers.deployContract("Keccak256HashHarness");
  });

  function verify(
    query: FriQuery,
    commitment: { roots: string[] },
    degreeBound: bigint = DEGREE_BOUND,
    blowupLog2: bigint = BLOWUP_LOG2
  ) {
    return harness.verifyQuery(degreeBound, blowupLog2, query, commitment);
  }

  describe("FOLD_DST", function () {
    // From `starkom_pcs::fri::tests::test_fold_dst`.
    it("matches the Rust implementation", async function () {
      expect(await harness.foldDst()).to.equal(
        "0x9ffd3556faeb2cae194ce95adf6b3580f590504daa0dea56966ce4ef233844af"
      );
    });
  });

  // Same cases as `starkom_pcs::fri::tests::test_reverse_*`.
  describe("reverseBits", function () {
    const cases: [bigint, bigint, bigint][] = [
      [0n, 0n, 0n],
      [0n, 1n, 0n],
      [1n, 1n, 1n],
      [0b000n, 3n, 0b000n],
      [0b001n, 3n, 0b100n],
      [0b011n, 3n, 0b110n],
      [0b101n, 3n, 0b101n],
      [0b110n, 3n, 0b011n],
      [0b1n, 62n, 1n << 61n],
      [0b1011n, 62n, 0b1101n << 58n],
      [ethers.MaxUint256, 256n, ethers.MaxUint256],
    ];
    for (const [index, numBits, expected] of cases) {
      it(`reverseBits(${index}, ${numBits}) = ${expected}`, async function () {
        expect(await harness.reverseBits(index, numBits)).to.equal(expected);
      });
    }
  });

  describe("foldingChallenge", function () {
    it("is the challenge of a one-element transcript with FOLD_DST", async function () {
      for (const root of honest.roots) {
        expect(await harness.foldingChallenge(root)).to.equal(
          await hashHarness.challenge(await harness.foldDst(), [root])
        );
      }
    });
  });

  describe("accepts honest proofs", function () {
    for (const testCase of cases) {
      const description =
        `${testCase.name} (degree bound ${testCase.degreeBound}, ` +
        `blowup 2^${testCase.blowupLog2}, all ${testCase.queries.length} queries)`;
      it(description, async function () {
        for (const query of testCase.queries) {
          await harness.verifyQuery(testCase.degreeBound, testCase.blowupLog2, query, {
            roots: testCase.roots,
          });
        }
      });
    }
  });

  // Mirrors the rejection tests in `starkom_pcs::fri::tests`.
  describe("rejects tampered proofs like the Rust implementation", function () {
    it("accepts the untampered proof", async function () {
      await verify(honestQuery(), honestCommitment());
    });

    it("rejects a foreign commitment", async function () {
      await expect(
        verify(honestQuery(), { roots: [...foreign.roots] })
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });

    it("rejects a corrupted root", async function () {
      const commitment = honestCommitment();
      commitment.roots[2] = "0x" + "aa".repeat(32);
      await expect(verify(honestQuery(), commitment)).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects truncated folds", async function () {
      const query = honestQuery();
      query.folds = query.folds.slice(0, 3);
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "WrongNumberOfFoldingRounds"
      );
    });

    it("rejects a truncated commitment", async function () {
      const commitment = honestCommitment();
      commitment.roots = commitment.roots.slice(0, 3);
      await expect(verify(honestQuery(), commitment)).to.be.revertedWithCustomError(
        harness,
        "WrongNumberOfFoldingRounds"
      );
    });

    it("rejects extra folds", async function () {
      const query = honestQuery();
      query.folds.push(structuredClone(query.folds[query.folds.length - 1]));
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "IncorrectProofSize"
      );
    });

    it("rejects folding stopped early", async function () {
      const query = honestQuery();
      query.folds = query.folds.slice(0, 3);
      const commitment = honestCommitment();
      commitment.roots = commitment.roots.slice(0, 3);
      await expect(verify(query, commitment)).to.be.revertedWithCustomError(
        harness,
        "FinalPolynomialNotConstant"
      );
    });

    it("rejects a wrong proof height", async function () {
      const query = honestQuery();
      query.folds[0] = honestQuery().folds[1];
      await expect(verify(query, honestCommitment()))
        .to.be.revertedWithCustomError(harness, "InvalidProofHeight")
        .withArgs(4n, 5n);
    });

    it("rejects swapped partners", async function () {
      const query = honestQuery();
      const proof = query.folds[0];
      const partner = BigInt(proof.path[0]);
      proof.path[0] = ethers.toBeHex(proof.value, 32);
      proof.value = partner;
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a tampered partner", async function () {
      const query = honestQuery();
      const proof = query.folds[1];
      proof.path[0] = ethers.toBeHex((BigInt(proof.path[0]) + 1n) % P, 32);
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a foreign leaf proof", async function () {
      const query = honestQuery();
      query.folds[1] = honestQuery(QUERY_INDEX + 4).folds[1];
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "LeafValueMismatch"
      );
    });

    it("rejects an out-of-range query index", async function () {
      const query = honestQuery();
      query.index = DEGREE_BOUND << BLOWUP_LOG2;
      await expect(verify(query, honestCommitment()))
        .to.be.revertedWithCustomError(harness, "InvalidQueryIndex")
        .withArgs(32n, 32n);
    });
  });

  // Checks performed by `Query::from_proto` in the Rust implementation.
  describe("rejects malformed queries like `Query::from_proto`", function () {
    it("rejects a zero degree bound", async function () {
      await expect(verify(honestQuery(), honestCommitment(), 0n))
        .to.be.revertedWithCustomError(harness, "InvalidDegreeBound")
        .withArgs(0n);
    });

    it("rejects a degree bound that is not a power of 2", async function () {
      await expect(verify(honestQuery(), honestCommitment(), 6n))
        .to.be.revertedWithCustomError(harness, "InvalidDegreeBound")
        .withArgs(6n);
    });

    it("rejects a zero blowup factor", async function () {
      await expect(
        verify(honestQuery(), honestCommitment(), DEGREE_BOUND, 0n)
      ).to.be.revertedWithCustomError(harness, "InvalidBlowupFactor");
    });

    it("rejects a domain that exceeds the 2-adicity of the field", async function () {
      await expect(verify(honestQuery(), honestCommitment(), 2n ** 60n, 3n))
        .to.be.revertedWithCustomError(harness, "DomainTooLarge")
        .withArgs(60n, 3n);
    });

    it("accepts a domain as large as the 2-adicity of the field", async function () {
      // 2^59 * 2^3 = 2^62 passes the parameter checks and only fails later on the proof heights.
      await expect(verify(honestQuery(), honestCommitment(), 2n ** 59n, 3n))
        .to.be.revertedWithCustomError(harness, "InvalidProofHeight")
        .withArgs(5n, 62n);
    });

    it("rejects a query without folds", async function () {
      const query = honestQuery();
      query.folds = [];
      await expect(verify(query, { roots: [] })).to.be.revertedWithCustomError(harness, "NoFolds");
    });

    it("rejects a non-canonical leaf value", async function () {
      const query = honestQuery();
      query.folds[2].value += P;
      await expect(verify(query, honestCommitment()))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(query.folds[2].value);
    });

    it("rejects a non-canonical partner", async function () {
      const query = honestQuery();
      const partner = BigInt(query.folds[0].path[0]) + P;
      query.folds[0].path[0] = ethers.toBeHex(partner, 32);
      await expect(verify(query, honestCommitment()))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(partner);
    });

    it("rejects an empty Merkle path", async function () {
      const query = honestQuery();
      query.folds[1].path = [];
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "MissingPartner"
      );
    });
  });

  describe("rejects other tampering", function () {
    it("rejects a tampered opened value", async function () {
      const query = honestQuery();
      query.folds[0].value = (query.folds[0].value + 1n) % P;
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a tampered partner value", async function () {
      const query = honestQuery();
      const partner = (BigInt(query.folds[0].path[0]) + 1n) % P;
      query.folds[0].path[0] = ethers.toBeHex(partner, 32);
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a consistently tampered folded value", async function () {
      // Changing a folded value breaks the consistency with the previous round.
      const query = honestQuery();
      query.folds[1].value = (query.folds[1].value + 1n) % P;
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "LeafValueMismatch"
      );
    });

    it("rejects a tampered final layer", async function () {
      // Replacing the final leaf with another constant breaks consistency with the previous round.
      const query = honestQuery();
      const last = query.folds[query.folds.length - 1];
      last.value = (last.value + 1n) % P;
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "LeafValueMismatch"
      );
    });

    it("rejects a tampered Merkle path", async function () {
      const query = honestQuery();
      query.folds[1].path[1] = ethers.ZeroHash;
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a proof for a different index", async function () {
      const query = honestQuery();
      query.index = BigInt(QUERY_INDEX + 1);
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects the wrong degree bound", async function () {
      await expect(
        verify(honestQuery(), honestCommitment(), DEGREE_BOUND / 2n, BLOWUP_LOG2 + 1n)
      ).to.be.revertedWithCustomError(harness, "IncorrectProofSize");
    });

    it("rejects the wrong blowup factor", async function () {
      await expect(
        verify(honestQuery(), honestCommitment(), DEGREE_BOUND, BLOWUP_LOG2 + 1n)
      ).to.be.revertedWithCustomError(harness, "InvalidProofHeight");
    });

    it("rejects a query from another commitment", async function () {
      await expect(
        verify(structuredClone(foreign.queries[QUERY_INDEX]), honestCommitment())
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });
  });
});
