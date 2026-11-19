// Compares the FRI settings of the Merkle lookup benchmark: proves it with every useful
// combination of fold rate and number of rounds, then measures the size and the gas cost of
// verifying every proof.
//
// Usage, from the root of the repository:
//
//   (cd tools/plonk-vectors && cargo run --release --bin merkle -- sweep /tmp/sweep)
//   SWEEP_DIRECTORY=/tmp/sweep npx hardhat run scripts/tune-merkle-fri.ts
//
// The proofs are blinded with random values, so the figures vary by a few bytes and a little gas
// between runs.

import { network } from "hardhat";
import { dataLength } from "ethers";
import { pathToFileURL } from "node:url";
import { type Measurement, measure } from "../test/benchmark";
import { loadPlonkCases } from "../test/vectors";

const { ethers } = await network.create();

const directory = process.env.SWEEP_DIRECTORY;
if (directory === undefined) {
  throw new Error("set SWEEP_DIRECTORY to the output directory of `merkle sweep`");
}

const harness = await ethers.deployContract("PlonkHarness");
const rows: { name: string; proofSize: number; result?: Measurement }[] = [];
for (const testCase of loadPlonkCases(pathToFileURL(directory + "/"))) {
  const proofSize = dataLength(testCase.scpf);
  try {
    rows.push({ name: testCase.name, proofSize, result: await measure(ethers, harness, testCase) });
  } catch {
    // The transaction doesn't fit in the gas limit of a transaction (EIP-7825).
    rows.push({ name: testCase.name, proofSize });
  }
}
// The cheapest first, and the proofs that don't fit in a transaction last.
const gas = (row: (typeof rows)[number]) => row.result?.totalGas ?? 2n ** 256n;
rows.sort((a, b) => (gas(a) < gas(b) ? -1 : gas(a) > gas(b) ? 1 : 0));
console.table(
  rows.map(({ name, proofSize, result }) => ({
    "FRI settings": name,
    "proof bytes": proofSize,
    "total gas": result === undefined ? "over the limit" : Number(result.totalGas),
    "calldata gas": result === undefined ? "" : Number(result.calldataGas),
    "EIP-7623 floor": result === undefined ? "" : Number(result.calldataFloorGas),
    "verification gas": result === undefined ? "" : Number(result.verificationGas),
    "floor binds": result === undefined ? "" : result.floorBinds,
  })),
);
