import type { HardhatEthers } from "@nomicfoundation/hardhat-ethers/types";
import { dataLength, getBytes } from "ethers";
import type { PlonkHarness } from "../types/ethers-contracts/index.js";
import type { PlonkCase } from "./vectors.js";

/** The base cost of a transaction. */
const TRANSACTION_GAS = 21000n;

/** The gas cost of a PLONK verification, measured with `PlonkHarness.check`. */
export interface Measurement {
  /** The size of the SCPF data of the proof, in bytes. */
  proofSize: number;
  /** The size of the calldata of the transaction, in bytes. */
  calldataSize: number;
  /** The gas of the whole transaction, as estimated by the node. */
  totalGas: bigint;
  /** The standard cost of the calldata: 4 gas per zero byte and 16 per non-zero byte (EIP-2028). */
  calldataGas: bigint;
  /**
   * The floor cost of the calldata, 10 gas per token with 1 token per zero byte and 4 per non-zero
   * byte (EIP-7623). A transaction pays at least the base cost plus this floor.
   */
  calldataFloorGas: bigint;
  /** The gas spent by the verification alone, measured with `PlonkHarness.verificationGas`. */
  verificationGas: bigint;
  /**
   * Whether the calldata floor (EIP-7623) determines the cost of the transaction, i.e. whether the
   * total is the base cost plus the floor rather than the standard cost of the calldata plus the
   * execution.
   */
  floorBinds: boolean;
}

/** Measures the gas cost of verifying the proof of a test case with `PlonkHarness.check`. */
export async function measure(
  ethers: HardhatEthers,
  harness: PlonkHarness,
  testCase: PlonkCase,
): Promise<Measurement> {
  const data = harness.interface.encodeFunctionData("check", [testCase.circuit, testCase.scpf]);
  const bytes = getBytes(data);
  const zeroBytes = BigInt(bytes.filter((byte) => byte === 0).length);
  const nonZeroBytes = BigInt(bytes.length) - zeroBytes;
  const totalGas = await ethers.provider.estimateGas({ to: await harness.getAddress(), data });
  const calldataFloorGas = 10n * (zeroBytes + 4n * nonZeroBytes);
  return {
    proofSize: dataLength(testCase.scpf),
    calldataSize: bytes.length,
    totalGas,
    calldataGas: 4n * zeroBytes + 16n * nonZeroBytes,
    calldataFloorGas,
    verificationGas: await harness.verificationGas(testCase.circuit, testCase.scpf),
    floorBinds: totalGas === TRANSACTION_GAS + calldataFloorGas,
  };
}
