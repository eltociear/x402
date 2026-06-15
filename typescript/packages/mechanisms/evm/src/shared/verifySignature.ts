import { hashTypedData, recoverAddress, isAddressEqual, getAddress, parseErc6492Signature } from "viem";
import type { TypedDataDomain } from "viem";
import type { FacilitatorEvmSigner } from "../signer";

/**
 * Parsed ERC-6492 classification for a payer address.
 *
 * `isCounterfactual` is true when the payment comes from an undeployed smart wallet
 * (ERC-6492 wrapper present, no bytecode at the payer address yet). In this case
 * pre-verification of the signature is deferred to on-chain simulation or settle.
 */
export type Erc6492Classification = {
  isCounterfactual: boolean;
  isDeployedAtPayer: boolean;
  hasDeploymentInfo: boolean;
  innerSignature: `0x${string}`;
  eip6492Deployment?: { factoryAddress: `0x${string}`; factoryCalldata: `0x${string}` };
};

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

/**
 * Classify an ERC-6492 payer in one RPC round-trip: parse the sig wrapper, fetch code,
 * and determine counterfactual vs deployed state.
 */
export async function classifyErc6492Payer(
  signer: FacilitatorEvmSigner,
  signature: `0x${string}`,
  payerAddress: `0x${string}`,
): Promise<Erc6492Classification> {
  const erc6492Data = parseErc6492Signature(signature);
  const hasDeploymentInfo = !!(
    erc6492Data.address &&
    erc6492Data.data &&
    !isAddressEqual(erc6492Data.address, ZERO_ADDRESS)
  );
  const innerSignature = hasDeploymentInfo ? erc6492Data.signature : signature;
  const eip6492Deployment = hasDeploymentInfo
    ? { factoryAddress: erc6492Data.address!, factoryCalldata: erc6492Data.data! }
    : undefined;

  let code: `0x${string}` | undefined;
  try {
    code = await signer.getCode({ address: payerAddress });
  } catch {
    code = undefined;
  }
  const isDeployedAtPayer = !!(code && code !== "0x");
  const isCounterfactual = hasDeploymentInfo && !isDeployedAtPayer;

  return { isCounterfactual, isDeployedAtPayer, hasDeploymentInfo, innerSignature, eip6492Deployment };
}

/**
 * Strict signature verification primitive that mirrors on-chain SignatureChecker
 * semantics exactly:
 *
 *   if signer.code.length == 0:
 *     ecrecover(digest, sig) == signer
 *   else:
 *     IERC1271(signer).isValidSignature(digest, sig) == 0x1626ba7e
 *
 * This matches:
 *   - Permit2 (libraries/SignatureVerification.sol)
 *   - USDC v2.2 (Circle's util/SignatureChecker.sol)
 *   - x402BatchSettlement (uses OpenZeppelin SignatureChecker)
 *
 * It deliberately does NOT fall back to ECDSA when EIP-1271 returns failure.
 * That fallback (which viem's `publicClient.verifyTypedData` performs) makes
 * pre-verify accept signatures that on-chain rejects — most visibly for
 * ERC-7702 delegated EOAs whose delegate's `isValidSignature` does not accept
 * raw owner ECDSA. With this primitive, pre-verify outcome == on-chain outcome.
 *
 * Plain EOAs (no code) take the ecrecover path and behave identically to before.
 * 7702-delegated EOAs take the EIP-1271 path because they have code; the delegate
 * decides — same as on-chain.
 */
const ERC1271_MAGIC_VALUE = "0x1626ba7e" as const;

const ERC1271_ABI = [
  {
    name: "isValidSignature",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "hash", type: "bytes32" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [{ name: "", type: "bytes4" }],
  },
] as const;

/** Verify a typed-data signature using strict on-chain SignatureChecker semantics. */
export async function verifyTypedDataSignature(
  signer: FacilitatorEvmSigner,
  params: {
    address: `0x${string}`;
    domain: TypedDataDomain;
    types: Record<string, readonly { name: string; type: string }[]>;
    primaryType: string;
    message: Record<string, unknown>;
    signature: `0x${string}`;
  },
): Promise<boolean> {
  let digest: `0x${string}`;
  try {
    digest = hashTypedData({
      domain: params.domain,
      types: params.types,
      primaryType: params.primaryType,
      message: params.message,
    });
  } catch {
    // Malformed typed data (e.g. non-checksummed address that viem rejects).
    // Treat as an invalid signature rather than propagating the error.
    return false;
  }
  return verifyHashSignature(signer, params.address, digest, params.signature);
}

/** Lower-level variant of {@link verifyTypedDataSignature} for callers that already have the digest. */
export async function verifyHashSignature(
  signer: FacilitatorEvmSigner,
  address: `0x${string}`,
  digest: `0x${string}`,
  signature: `0x${string}`,
): Promise<boolean> {
  // getCode must be guarded: a transient RPC error should return false (invalid sig
  // semantics) rather than propagating as an unhandled rejection. All callers rely on
  // this function returning a boolean, never throwing.
  let code: `0x${string}` | undefined;
  try {
    code = await signer.getCode({ address });
  } catch {
    return false;
  }
  return verifyHashSignatureWithCode(signer, address, code, digest, signature);
}

/**
 * Like {@link verifyHashSignature} but accepts pre-fetched bytecode to avoid a
 * redundant `eth_getCode` RPC when the caller already has it (e.g. after the
 * ERC-6492 counterfactual check in {@link classifyErc6492Payer}).
 *
 * Pass `undefined` or `"0x"` for `code` to take the EOA (ecrecover) path.
 */
export function verifyHashSignatureWithCode(
  signer: FacilitatorEvmSigner,
  address: `0x${string}`,
  code: `0x${string}` | undefined,
  digest: `0x${string}`,
  signature: `0x${string}`,
): Promise<boolean> {
  if (!code || code === "0x") {
    return verifyECDSA(address, digest, signature);
  }
  return verifyERC1271(signer, address, digest, signature);
}

/** ecrecover path — used when the address has no code. */
export async function verifyECDSA(
  address: `0x${string}`,
  digest: `0x${string}`,
  signature: `0x${string}`,
): Promise<boolean> {
  const sigHex = signature.startsWith("0x") ? signature.slice(2) : signature;
  if (sigHex.length !== 130) return false;
  try {
    const recovered = await recoverAddress({ hash: digest, signature });
    return isAddressEqual(getAddress(recovered), getAddress(address));
  } catch {
    return false;
  }
}

/** Strict EIP-1271 path — returns false on revert or non-magic return, never falls back to ECDSA. */
export async function verifyERC1271(
  signer: FacilitatorEvmSigner,
  address: `0x${string}`,
  digest: `0x${string}`,
  signature: `0x${string}`,
): Promise<boolean> {
  try {
    const result = (await signer.readContract({
      address,
      abi: ERC1271_ABI,
      functionName: "isValidSignature",
      args: [digest, signature],
    })) as `0x${string}` | undefined;
    if (typeof result !== "string") return false;
    return result.toLowerCase().startsWith(ERC1271_MAGIC_VALUE);
  } catch {
    return false;
  }
}
