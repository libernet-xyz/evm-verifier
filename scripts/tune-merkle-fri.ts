// Compares the FRI settings of a Merkle lookup benchmark: proves it with every useful combination
// of fold rate and number of rounds, then measures the size and the gas cost of verifying every
// proof.
//
// Usage, from the root of the repository, where `<benchmark>` is a benchmark of
// `tools/plonk-vectors/src/bin/merkle.rs`, e.g. `ternary-162-t5x7`:
//
//   (cd tools/plonk-vectors && cargo run --release --bin merkle -- sweep <benchmark> /tmp/sweep)
//   SWEEP_DIRECTORY=/tmp/sweep \
//     npx hardhat run --build-profile production scripts/tune-merkle-fri.ts
//
// Every proof is measured under the current calldata pricing (Osaka, EIP-7623) and under Amsterdam,
// where EIP-7976 raises the calldata floor to 64 gas per byte. The table is sorted by the size of
// the proof, or by the total gas with `TARGET=osaka` or `TARGET=amsterdam`. Amsterdam is
// experimental in Hardhat: its base transaction cost is 15,000 gas rather than 21,000.
//
// The proofs are blinded with random values, so the figures vary by a few hundred bytes and a
// little gas between runs.

import { network } from "hardhat";
import { dataLength } from "ethers";
import { pathToFileURL } from "node:url";
import { type Measurement, measure } from "../test/benchmark.js";
import { loadPlonkCases } from "../test/vectors.js";

const directory = process.env.SWEEP_DIRECTORY;
if (directory === undefined) {
  throw new Error("set SWEEP_DIRECTORY to the output directory of `merkle sweep`");
}
const target = process.env.TARGET ?? "size";
if (target !== "size" && target !== "osaka" && target !== "amsterdam") {
  throw new Error("TARGET must be `size`, `osaka` or `amsterdam`");
}

const osaka = (await network.create()).ethers;
const amsterdam = (await network.create({ override: { hardfork: "amsterdam" } })).ethers;
const osakaHarness = await osaka.deployContract("PlonkHarness");
const amsterdamHarness = await amsterdam.deployContract("PlonkHarness");
const amsterdamAddress = await amsterdamHarness.getAddress();

const rows: {
  name: string;
  proofSize: number;
  calldataSize: number;
  osaka?: Measurement;
  amsterdamGas?: bigint;
}[] = [];
for (const testCase of loadPlonkCases(pathToFileURL(directory + "/"))) {
  const data = osakaHarness.interface.encodeFunctionData("check", [
    testCase.circuit,
    testCase.scpf,
  ]);
  // Both estimates throw if the transaction doesn't fit in the gas limit of a transaction
  // (EIP-7825).
  const row: (typeof rows)[number] = {
    name: testCase.name,
    proofSize: dataLength(testCase.scpf),
    calldataSize: dataLength(data),
  };
  try {
    row.osaka = await measure(osaka, osakaHarness, testCase);
  } catch {}
  try {
    row.amsterdamGas = await amsterdam.provider.estimateGas({ to: amsterdamAddress, data });
  } catch {}
  rows.push(row);
}

// The smallest or the cheapest first, and the proofs that don't fit in a transaction last.
const key = (row: (typeof rows)[number]) =>
  target === "size"
    ? BigInt(row.proofSize)
    : ((target === "osaka" ? row.osaka?.totalGas : row.amsterdamGas) ?? 2n ** 256n);
rows.sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
const overTheLimit = "over the limit";
console.table(
  rows.map(({ name, proofSize, calldataSize, osaka, amsterdamGas }) => ({
    "FRI settings": name,
    "proof bytes": proofSize,
    "calldata bytes": calldataSize,
    "Osaka total gas": osaka === undefined ? overTheLimit : Number(osaka.totalGas),
    "Osaka floor binds": osaka?.floorBinds ?? "",
    "Amsterdam total gas": amsterdamGas === undefined ? overTheLimit : Number(amsterdamGas),
    "verification gas": osaka === undefined ? "" : Number(osaka.verificationGas),
  })),
);
