import { expect } from "chai";
import { network } from "hardhat";
import type { FriHarness, Keccak256HashHarness } from "../types/ethers-contracts";
import {
  encodeFriQueries,
  type FriCommitment,
  type FriOptions,
  type FriQuery,
  loadFriCases,
} from "./vectors";

const { ethers } = await network.create();

const P = 0x7ffffffffffffffffffffffffffffffe0673ddf29e9b5547c000000000000001n;

const UNLIMITED = 2n ** 64n - 1n;

const cases = loadFriCases();

function findCase(name: string) {
  return cases.find((testCase) => testCase.name === name)!;
}

// Same setup as the unit tests in `starkom_pcs::fri`.
const honest = findCase("polynomial of degree 7");
const foreign = findCase("foreign polynomial of degree 7");
const OPTIONS: FriOptions = honest.options;
const QUERY_INDEX = 3;

function honestQuery(index: number = QUERY_INDEX): FriQuery {
  return structuredClone(honest.queries[index]);
}

function honestCommitment(): FriCommitment {
  return structuredClone(honest.commitment);
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

/**
 * Returns the position of the value at the queried index within the pair opened by
 * `honestQuery()` in the given round.
 */
function queriedOffset(round: number): number {
  const k = BigInt(OPTIONS.degreeBound.toString(2).length - 1) + OPTIONS.blowupLog2 - BigInt(round);
  const index = BigInt(QUERY_INDEX) % (1n << k);
  return Number(reverseBits(index, k) & 1n);
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
    commitment: FriCommitment,
    value: bigint = honest.values[QUERY_INDEX],
    options: FriOptions = OPTIONS
  ) {
    return harness.verifyQuery(options, encodeFriQueries([query]), query.index, commitment, value);
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

  // Same cases as `starkom_pcs::fri::tests::test_num_rounds_*`.
  describe("numRounds", function () {
    const cases: [bigint, bigint, bigint, bigint][] = [
      [1n, 1n, UNLIMITED, 0n],
      [8n, 1n, UNLIMITED, 3n],
      [64n, 3n, UNLIMITED, 2n],
      [16384n, 3n, UNLIMITED, 4n],
      [8n, 1n, 0n, 0n],
      [8n, 1n, 2n, 2n],
      [16384n, 3n, 2n, 2n],
      [16384n, 3n, 4n, 4n],
      [16384n, 3n, 5n, 4n],
      [4n, 3n, UNLIMITED, 0n],
      [128n, 8n, UNLIMITED, 0n],
      [8n, 1n, ethers.MaxUint256, 3n],
    ];
    for (const [degreeBound, foldRate, maxRounds, expected] of cases) {
      it(`numRounds(${degreeBound}, ${foldRate}, ${maxRounds}) = ${expected}`, async function () {
        expect(await harness.numRounds(degreeBound, foldRate, maxRounds)).to.equal(expected);
      });
    }
  });

  describe("foldingChallenge", function () {
    it("is the challenge of a one-element transcript with FOLD_DST", async function () {
      for (const root of honest.commitment.roots) {
        expect(await harness.foldingChallenge(root)).to.equal(
          await hashHarness.challenge(await harness.foldDst(), [root])
        );
      }
    });
  });

  describe("accepts honest proofs", function () {
    for (const { name, options, commitment, queries, values } of cases) {
      const maxRounds = options.maxRounds === UNLIMITED ? "unlimited" : `${options.maxRounds}`;
      const description =
        `${name} (degree bound ${options.degreeBound}, blowup 2^${options.blowupLog2}, ` +
        `fold rate ${options.foldRate}, max rounds ${maxRounds}, ` +
        `${commitment.roots.length} rounds, all ${queries.length} queries)`;
      it(description, async function () {
        await harness.verifyQueries(
          options,
          encodeFriQueries(queries),
          queries.map((query) => query.index),
          commitment,
          values
        );
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
        verify(honestQuery(), structuredClone(foreign.commitment))
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
      query.folds = query.folds.slice(0, 2);
      await expect(verify(query, honestCommitment())).to.revert(ethers);
    });

    it("rejects a truncated commitment", async function () {
      const commitment = honestCommitment();
      commitment.roots = commitment.roots.slice(0, 2);
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
        "TrailingData"
      );
    });

    it("rejects folding stopped early", async function () {
      const query = honestQuery();
      query.folds = query.folds.slice(0, 2);
      const commitment = honestCommitment();
      commitment.roots = commitment.roots.slice(0, 2);
      await expect(verify(query, commitment)).to.be.revertedWithCustomError(
        harness,
        "WrongNumberOfFoldingRounds"
      );
    });

    it("rejects a tampered folded polynomial", async function () {
      const commitment = honestCommitment();
      commitment.foldedPolynomial[0] = (commitment.foldedPolynomial[0] + 1n) % P;
      await expect(verify(honestQuery(), commitment)).to.be.revertedWithCustomError(
        harness,
        "FoldedPolynomialMismatch"
      );
    });

    it("rejects an oversized folded polynomial", async function () {
      const commitment = honestCommitment();
      commitment.foldedPolynomial.push(0n);
      await expect(verify(honestQuery(), commitment))
        .to.be.revertedWithCustomError(harness, "InvalidFoldedPolynomialSize")
        .withArgs(2n, 1n);
    });

    it("rejects an oversized folded polynomial without rounds", async function () {
      const testCase = findCase("polynomial of degree 7 without rounds");
      const commitment = structuredClone(testCase.commitment);
      commitment.foldedPolynomial.push(0n);
      await expect(
        verify(
          structuredClone(testCase.queries[QUERY_INDEX]),
          commitment,
          testCase.values[QUERY_INDEX],
          testCase.options
        )
      )
        .to.be.revertedWithCustomError(harness, "InvalidFoldedPolynomialSize")
        .withArgs(9n, 8n);
    });

    it("accepts a trimmed folded polynomial", async function () {
      // The polynomial has degree less than 2, so after one round its folded polynomial has 4
      // coefficients of which only the first is non-zero. A shorter folded polynomial proves a
      // stronger degree bound.
      const testCase = findCase("low-degree polynomial with one round");
      const commitment = structuredClone(testCase.commitment);
      expect(commitment.foldedPolynomial.slice(1)).to.deep.equal([0n, 0n, 0n]);
      commitment.foldedPolynomial = commitment.foldedPolynomial.slice(0, 1);
      await verify(
        structuredClone(testCase.queries[QUERY_INDEX]),
        commitment,
        testCase.values[QUERY_INDEX],
        testCase.options
      );
    });

    it("rejects a wrong proof height", async function () {
      const query = honestQuery();
      query.folds[0] = honestQuery().folds[1];
      await expect(verify(query, honestCommitment())).to.revert(ethers);
    });

    it("rejects a wrong value", async function () {
      const value = (honest.values[QUERY_INDEX] + 1n) % P;
      await expect(verify(honestQuery(), honestCommitment(), value)).to.be.revertedWithCustomError(
        harness,
        "LeafValueMismatch"
      );
    });

    it("rejects a wrong value without rounds", async function () {
      const testCase = findCase("polynomial of degree 7 without rounds");
      const value = (testCase.values[QUERY_INDEX] + 1n) % P;
      await expect(
        verify(
          structuredClone(testCase.queries[QUERY_INDEX]),
          structuredClone(testCase.commitment),
          value,
          testCase.options
        )
      ).to.be.revertedWithCustomError(harness, "FoldedPolynomialMismatch");
    });

    it("rejects swapped partners", async function () {
      const query = honestQuery();
      query.folds[0].coset.reverse();
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "LeafValueMismatch"
      );
    });

    it("rejects a tampered partner", async function () {
      const query = honestQuery();
      const coset = query.folds[1].coset;
      const offset = queriedOffset(1) ^ 1;
      coset[offset] = (coset[offset] + 1n) % P;
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
      query.index = OPTIONS.degreeBound << OPTIONS.blowupLog2;
      await expect(verify(query, honestCommitment()))
        .to.be.revertedWithCustomError(harness, "InvalidQueryIndex")
        .withArgs(32n, 32n);
    });

    describe("with fold rate 3", function () {
      // The queried value of index 3 is at position 48 = 0b110000 of the first tree, that is at
      // offset 0 of its coset.
      const testCase = findCase("polynomial of degree 15 with fold rate 3");

      function verifyCoset(query: FriQuery, options: FriOptions = testCase.options) {
        return verify(
          query,
          structuredClone(testCase.commitment),
          testCase.values[QUERY_INDEX],
          options
        );
      }

      it("accepts the untampered proof", async function () {
        await verifyCoset(structuredClone(testCase.queries[QUERY_INDEX]));
      });

      it("rejects a tampered coset leaf", async function () {
        const query = structuredClone(testCase.queries[QUERY_INDEX]);
        query.folds[0].coset[4] = (query.folds[0].coset[4] + 1n) % P;
        await expect(verifyCoset(query)).to.be.revertedWithCustomError(harness, "RootHashMismatch");
      });

      it("rejects swapped coset leaves", async function () {
        const query = structuredClone(testCase.queries[QUERY_INDEX]);
        const coset = query.folds[0].coset;
        [coset[1], coset[2]] = [coset[2], coset[1]];
        await expect(verifyCoset(query)).to.be.revertedWithCustomError(harness, "RootHashMismatch");
      });

      it("rejects a wrong fold rate", async function () {
        const options = { ...testCase.options, foldRate: 2n };
        await expect(
          verifyCoset(structuredClone(testCase.queries[QUERY_INDEX]), options)
        ).to.be.revertedWithCustomError(harness, "WrongNumberOfFoldingRounds");
      });
    });

    it("rejects a query with the wrong fold rate", async function () {
      await expect(
        verify(honestQuery(), honestCommitment(), honest.values[QUERY_INDEX], {
          ...OPTIONS,
          foldRate: 3n,
        })
      ).to.be.revertedWithCustomError(harness, "WrongNumberOfFoldingRounds");
    });
  });

  // Checks performed by `Query::from_proto` and `Proof::from_proto` in the Rust implementation.
  describe("rejects malformed queries like `from_proto`", function () {
    function verifyWith(options: Partial<FriOptions>) {
      return verify(honestQuery(), honestCommitment(), honest.values[QUERY_INDEX], {
        ...OPTIONS,
        ...options,
      });
    }

    it("rejects a zero degree bound", async function () {
      await expect(verifyWith({ degreeBound: 0n }))
        .to.be.revertedWithCustomError(harness, "InvalidDegreeBound")
        .withArgs(0n);
    });

    it("rejects a degree bound that is not a power of 2", async function () {
      await expect(verifyWith({ degreeBound: 6n }))
        .to.be.revertedWithCustomError(harness, "InvalidDegreeBound")
        .withArgs(6n);
    });

    it("rejects a zero blowup factor", async function () {
      await expect(verifyWith({ blowupLog2: 0n })).to.be.revertedWithCustomError(
        harness,
        "InvalidBlowupFactor"
      );
    });

    it("rejects a zero fold rate", async function () {
      await expect(verifyWith({ foldRate: 0n })).to.be.revertedWithCustomError(
        harness,
        "InvalidFoldRate"
      );
    });

    it("rejects a domain that exceeds the 2-adicity of the field", async function () {
      await expect(verifyWith({ degreeBound: 2n ** 60n, blowupLog2: 3n }))
        .to.be.revertedWithCustomError(harness, "DomainTooLarge")
        .withArgs(60n, 3n);
    });

    it("accepts a domain as large as the 2-adicity of the field", async function () {
      // 2^59 * 2^3 = 2^62 passes the parameter checks and only fails later on the number of
      // rounds.
      await expect(
        verifyWith({ degreeBound: 2n ** 59n, blowupLog2: 3n })
      ).to.be.revertedWithCustomError(harness, "WrongNumberOfFoldingRounds");
    });

    it("rejects a non-canonical coset value", async function () {
      const query = honestQuery();
      query.folds[2].coset[0] += P;
      await expect(verify(query, honestCommitment()))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(query.folds[2].coset[0]);
    });

    it("rejects another non-canonical coset value", async function () {
      const query = honestQuery();
      query.folds[0].coset[1] += P;
      await expect(verify(query, honestCommitment()))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(query.folds[0].coset[1]);
    });

    it("rejects a missing coset value", async function () {
      const query = honestQuery();
      query.folds[1].coset.pop();
      await expect(verify(query, honestCommitment())).to.revert(ethers);
    });

    it("rejects an extra coset value", async function () {
      const query = honestQuery();
      query.folds[1].coset.push(42n);
      await expect(verify(query, honestCommitment())).to.revert(ethers);
    });

    it("rejects a non-canonical coefficient of the folded polynomial", async function () {
      const commitment = honestCommitment();
      commitment.foldedPolynomial[0] += P;
      await expect(verify(honestQuery(), commitment))
        .to.be.revertedWithCustomError(harness, "NonCanonicalScalar")
        .withArgs(commitment.foldedPolynomial[0]);
    });
  });

  describe("rejects other tampering", function () {
    it("rejects a tampered opened value", async function () {
      const query = honestQuery();
      const coset = query.folds[0].coset;
      const offset = queriedOffset(0);
      coset[offset] = (coset[offset] + 1n) % P;
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "LeafValueMismatch"
      );
    });

    it("rejects a tampered partner value", async function () {
      const query = honestQuery();
      const coset = query.folds[0].coset;
      const offset = queriedOffset(0) ^ 1;
      coset[offset] = (coset[offset] + 1n) % P;
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "RootHashMismatch"
      );
    });

    it("rejects a consistently tampered folded value", async function () {
      // Changing a folded value breaks the consistency with the previous round.
      const query = honestQuery();
      const coset = query.folds[1].coset;
      const offset = queriedOffset(1);
      coset[offset] = (coset[offset] + 1n) % P;
      await expect(verify(query, honestCommitment())).to.be.revertedWithCustomError(
        harness,
        "LeafValueMismatch"
      );
    });

    it("rejects a tampered last round", async function () {
      const query = honestQuery();
      const round = query.folds.length - 1;
      const coset = query.folds[round].coset;
      const offset = queriedOffset(round);
      coset[offset] = (coset[offset] + 1n) % P;
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
        verify(honestQuery(), honestCommitment(), honest.values[QUERY_INDEX], {
          ...OPTIONS,
          degreeBound: OPTIONS.degreeBound / 2n,
          blowupLog2: OPTIONS.blowupLog2 + 1n,
        })
      ).to.be.revertedWithCustomError(harness, "WrongNumberOfFoldingRounds");
    });

    it("rejects the wrong blowup factor", async function () {
      await expect(
        verify(honestQuery(), honestCommitment(), honest.values[QUERY_INDEX], {
          ...OPTIONS,
          blowupLog2: OPTIONS.blowupLog2 + 1n,
        })
      ).to.revert(ethers);
    });

    it("rejects a query from another commitment", async function () {
      await expect(
        verify(
          structuredClone(foreign.queries[QUERY_INDEX]),
          honestCommitment(),
          foreign.values[QUERY_INDEX]
        )
      ).to.be.revertedWithCustomError(harness, "RootHashMismatch");
    });
  });
});
