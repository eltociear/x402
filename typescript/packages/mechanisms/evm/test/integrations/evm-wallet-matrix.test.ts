/**
 * Wallet compatibility matrix integration tests — TypeScript SDK.
 *
 * Exercises the full x402 payment flow (verify + settle) for every supported
 * combination documented in docs/advanced-concepts/wallet-compatibility.mdx.
 *
 * Wallet types tested:
 *   A - Plain EOA
 *   B - Deployed ERC-4337-style smart account (SimpleWallet, permissive EIP-1271)
 *   C - ERC-6492 counterfactual — fresh wallet generated per run, deployed during settle
 *   D - ERC-7702 EOA delegated to PermissiveECDSADelegate
 *
 * Schemes tested per wallet:
 *   - exact / EIP-3009 (transferWithAuthorization)
 *   - exact / Permit2 (permitWitnessTransferFrom)  — wallets A, D (B requires smart-account execute, C is ❌)
 *   - upto  / Permit2                              — wallets A, D
 *
 * Required env vars (from typescript/packages/mechanisms/evm/.env):
 *   CLIENT_PRIVATE_KEY, FACILITATOR_PRIVATE_KEY
 *   CLIENT_4337_ADDRESS, CLIENT_4337_OWNER_PRIVATE_KEY
 *   CLIENT_6492_OWNER_PRIVATE_KEY, CLIENT_6492_FACTORY, CLIENT_6492_SALT
 *   CLIENT_7702_PRIVATE_KEY, CLIENT_7702_ADDRESS
 *   SIMPLE_WALLET_FACTORY, WALLET_B_SALT
 *
 * Each test carries { timeout: 60000 } — Base Sepolia txs can take 5–30 s.
 */

import { describe, it, expect, beforeAll } from "vitest";
import {
  createPublicClient,
  createWalletClient,
  http,
  encodeAbiParameters,
  parseAbiParameters,
  concat,
  getAddress,
  maxUint256,
  encodeFunctionData,
  keccak256,
  toBytes,
} from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import { x402Client } from "@x402/core/client";
import { x402Facilitator } from "@x402/core/facilitator";
import { x402ResourceServer, FacilitatorClient } from "@x402/core/server";
import type {
  PaymentPayload,
  PaymentRequirements,
  VerifyResponse,
  SettleResponse,
  SupportedResponse,
  Network,
} from "@x402/core/types";
import {
  ExactEvmScheme as ExactEvmClient,
  UptoEvmScheme as UptoEvmClient,
  toFacilitatorEvmSigner,
} from "../../src";
import { ExactEvmScheme as ExactEvmServer } from "../../src/exact/server/scheme";
import { UptoEvmScheme as UptoEvmServer } from "../../src/upto/server/scheme";
import { ExactEvmScheme as ExactEvmFacilitator } from "../../src/exact/facilitator/scheme";

// ─── Environment ──────────────────────────────────────────────────────────────

const env = {
  FACILITATOR_PRIVATE_KEY: process.env.FACILITATOR_PRIVATE_KEY as `0x${string}` | undefined,
  CLIENT_PRIVATE_KEY:      process.env.CLIENT_PRIVATE_KEY as `0x${string}` | undefined,
  CLIENT_4337_ADDRESS:     process.env.CLIENT_4337_ADDRESS as `0x${string}` | undefined,
  CLIENT_4337_OWNER_PRIVATE_KEY: process.env.CLIENT_4337_OWNER_PRIVATE_KEY as `0x${string}` | undefined,
  CLIENT_6492_OWNER_PRIVATE_KEY: process.env.CLIENT_6492_OWNER_PRIVATE_KEY as `0x${string}` | undefined,
  CLIENT_6492_FACTORY:     process.env.CLIENT_6492_FACTORY as `0x${string}` | undefined,
  CLIENT_6492_SALT:        process.env.CLIENT_6492_SALT as `0x${string}` | undefined,
  CLIENT_7702_PRIVATE_KEY: process.env.CLIENT_7702_PRIVATE_KEY as `0x${string}` | undefined,
  CLIENT_7702_ADDRESS:     process.env.CLIENT_7702_ADDRESS as `0x${string}` | undefined,
  SIMPLE_WALLET_FACTORY:   process.env.SIMPLE_WALLET_FACTORY as `0x${string}` | undefined,
  WALLET_B_SALT:           process.env.WALLET_B_SALT as `0x${string}` | undefined,
};

// ─── Constants ────────────────────────────────────────────────────────────────

const NETWORK: Network = "eip155:84532";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const PAYMENT_AMOUNT = "100"; // 0.0001 USDC per test
const ERC6492_MAGIC = "0x6492649264926492649264926492649264926492649264926492649264926492";

const FACTORY_ABI = [
  {
    name: "createWallet",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "_owner", type: "address" }, { name: "_salt", type: "bytes32" }],
    outputs: [{ type: "address" }],
  },
] as const;

const USDC_ABI = [
  { name: "approve", type: "function", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
  { name: "allowance", type: "function", stateMutability: "view", inputs: [{ type: "address" }, { type: "address" }], outputs: [{ type: "uint256" }] },
  { name: "transfer", type: "function", stateMutability: "nonpayable", inputs: [{ type: "address" }, { type: "uint256" }], outputs: [{ type: "bool" }] },
  { name: "balanceOf", type: "function", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
] as const;

// ─── Shared infrastructure ────────────────────────────────────────────────────

class LocalFacilitatorClient implements FacilitatorClient {
  constructor(private readonly facilitator: x402Facilitator) {}
  verify(p: PaymentPayload, r: PaymentRequirements): Promise<VerifyResponse> { return this.facilitator.verify(p, r); }
  settle(p: PaymentPayload, r: PaymentRequirements): Promise<SettleResponse> { return this.facilitator.settle(p, r); }
  getSupported(): Promise<SupportedResponse> { return Promise.resolve(this.facilitator.getSupported()); }
}

function buildFacilitator(facilitatorKey: `0x${string}`, factoryAllowlist?: string[]) {
  const pc = createPublicClient({ chain: baseSepolia, transport: http() });
  const facilAcct = privateKeyToAccount(facilitatorKey);
  const facilWc = createWalletClient({ account: facilAcct, chain: baseSepolia, transport: http() });

  const facilitatorSigner = toFacilitatorEvmSigner({
    address: facilAcct.address,
    // Use simulateContract (not readContract) so the eth_call includes
    // account=facilitator. This matters for upto/Permit2 where x402UptoPermit2Proxy
    // checks msg.sender == witness.facilitator during simulation.
    readContract: async args => {
      const r = await pc.simulateContract({
        account: facilAcct,
        address: args.address,
        abi: args.abi as never,
        functionName: args.functionName,
        args: (args.args || []) as never,
      });
      return r.result;
    },
    verifyTypedData: args => pc.verifyTypedData(args as never),
    writeContract: args => facilWc.writeContract({ ...args, args: args.args || [] } as never),
    sendTransaction: args => facilWc.sendTransaction(args),
    waitForTransactionReceipt: args => pc.waitForTransactionReceipt(args),
    getCode: args => pc.getCode(args),
  });

  const evmFacilitator = new ExactEvmFacilitator(facilitatorSigner, {
    eip6492AllowedFactories: factoryAllowlist ?? (env.SIMPLE_WALLET_FACTORY ? [env.SIMPLE_WALLET_FACTORY] : []),
  });
  const facilitator = new x402Facilitator().register(NETWORK, evmFacilitator);
  return { facilitator, facilAcct, facilWc, pc, facilitatorSigner };
}

function buildExactServer(facilitatorKey: `0x${string}`, factoryAllowlist?: string[]) {
  const { facilitator, facilAcct } = buildFacilitator(facilitatorKey, factoryAllowlist);
  const server = new x402ResourceServer(new LocalFacilitatorClient(facilitator));
  server.register(NETWORK, new ExactEvmServer());
  return { server, facilAcct };
}

function makeErc6492Sig(
  innerSig: `0x${string}`,
  factory: `0x${string}`,
  factoryCalldata: `0x${string}`,
): `0x${string}` {
  const encoded = encodeAbiParameters(
    parseAbiParameters("address, bytes, bytes"),
    [factory, factoryCalldata, innerSig],
  );
  return concat([encoded, ERC6492_MAGIC]) as `0x${string}`;
}

/** Compute CREATE2 address for SimpleWallet without RPC. */
function computeWalletAddress(factoryAddr: `0x${string}`, owner: `0x${string}`, salt: `0x${string}`): `0x${string}` {
  // SimpleWallet init bytecode hash (from compiled artifact)
  // creationCode = SimpleWallet bytecode with owner address ABI-encoded appended
  // We use the factory's getAddress via raw eth_call — same result, avoids hardcoding bytecode hash.
  // In practice, always call factoryGetAddress so we don't have to embed the bytecode hash here.
  throw new Error("Use factoryGetAddress instead");
}

/** Call factory.getAddress(owner, salt) via raw eth_call — avoids viem readContract ABI quirk. */
async function factoryGetAddress(
  pc: ReturnType<typeof createPublicClient>,
  factory: `0x${string}`,
  owner: `0x${string}`,
  salt: `0x${string}`,
): Promise<`0x${string}`> {
  const sel = keccak256(toBytes("getAddress(address,bytes32)")).slice(0, 10);
  const args = encodeAbiParameters(parseAbiParameters("address, bytes32"), [owner, salt]);
  const { data } = await pc.call({ to: factory, data: (sel + args.slice(2)) as `0x${string}` });
  return ("0x" + data!.slice(-40)) as `0x${string}`;
}

function buildExactEip3009Accepts(payTo: string): PaymentRequirements[] {
  return [{
    scheme: "exact" as const,
    network: NETWORK,
    asset: USDC,
    amount: PAYMENT_AMOUNT,
    payTo,
    maxTimeoutSeconds: 3600,
    extra: { name: "USDC", version: "2" },
  }];
}

function buildExactPermit2Accepts(payTo: string): PaymentRequirements[] {
  return [{
    scheme: "exact" as const,
    network: NETWORK,
    asset: USDC,
    amount: PAYMENT_AMOUNT,
    payTo,
    maxTimeoutSeconds: 3600,
    extra: { name: "USDC", version: "2", assetTransferMethod: "permit2" },
  }];
}

function buildUptoPermit2Accepts(payTo: string, facilitatorAddr: string): PaymentRequirements[] {
  return [{
    scheme: "upto" as const,
    network: NETWORK,
    asset: USDC,
    amount: PAYMENT_AMOUNT,
    payTo,
    maxTimeoutSeconds: 3600,
    extra: { name: "USDC", version: "2", assetTransferMethod: "permit2", facilitatorAddress: facilitatorAddr },
  }];
}

async function runExactFlow(
  clientAcct: ReturnType<typeof privateKeyToAccount>,
  accepts: PaymentRequirements[],
  server: x402ResourceServer,
  label: string,
  sigOverride?: `0x${string}`,
): Promise<SettleResponse> {
  const evmClient = new ExactEvmClient(clientAcct);
  const client = new x402Client().register(NETWORK, evmClient);
  await server.initialize();

  const paymentRequired = await server.createPaymentRequiredResponse(accepts, {
    url: "https://test.x402.org", description: label, mimeType: "application/json",
  });
  const payload = await client.createPaymentPayload(paymentRequired);
  if (sigOverride && payload.payload && typeof payload.payload === "object") {
    (payload.payload as Record<string, unknown>).signature = sigOverride;
  }

  const accepted = server.findMatchingRequirements(accepts, payload);
  expect(accepted).toBeDefined();

  const verifyResp = await server.verifyPayment(payload, accepted!);
  expect(verifyResp.isValid, `${label}: verify failed: ${verifyResp.invalidReason}`).toBe(true);

  const settleResp = await server.settlePayment(payload, accepted!);
  expect(settleResp.success, `${label}: settle failed: ${settleResp.errorReason}`).toBe(true);
  console.log(`${label} ✅ tx=${settleResp.transaction}`);
  return settleResp;
}

async function runUptoFlow(
  clientAcct: ReturnType<typeof privateKeyToAccount>,
  accepts: PaymentRequirements[],
  facilitatorKey: `0x${string}`,
  label: string,
): Promise<SettleResponse> {
  const pc = createPublicClient({ chain: baseSepolia, transport: http() });
  const facilAcct = privateKeyToAccount(facilitatorKey);
  const facilWc = createWalletClient({ account: facilAcct, chain: baseSepolia, transport: http() });

  const facilitatorSigner = toFacilitatorEvmSigner({
    address: facilAcct.address,
    // simulateContract sets account=facilAcct so msg.sender==witness.facilitator in upto simulation
    readContract: async args => {
      const r = await pc.simulateContract({ account: facilAcct, address: args.address, abi: args.abi as never, functionName: args.functionName, args: (args.args || []) as never });
      return r.result;
    },
    verifyTypedData: args => pc.verifyTypedData(args as never),
    writeContract: args => facilWc.writeContract({ ...args, args: args.args || [] } as never),
    sendTransaction: args => facilWc.sendTransaction(args),
    waitForTransactionReceipt: args => pc.waitForTransactionReceipt(args),
    getCode: args => pc.getCode(args),
  });

  // Upto uses ExactEvmFacilitator for the facilitator but UptoEvmScheme for client/server
  const { UptoEvmScheme: UptoEvmFacilitator } = await import("../../src/upto/facilitator/scheme");
  const uptoFacilitator = new UptoEvmFacilitator(facilitatorSigner);
  const facilitator = new x402Facilitator().register(NETWORK, uptoFacilitator);
  const server = new x402ResourceServer(new LocalFacilitatorClient(facilitator));
  server.register(NETWORK, new UptoEvmServer());
  await server.initialize();

  const evmClient = new UptoEvmClient(clientAcct);
  const client = new x402Client().register(NETWORK, evmClient);

  const paymentRequired = await server.createPaymentRequiredResponse(accepts, {
    url: "https://test.x402.org", description: label, mimeType: "application/json",
  });
  const payload = await client.createPaymentPayload(paymentRequired);
  const accepted = server.findMatchingRequirements(accepts, payload);
  expect(accepted).toBeDefined();

  const verifyResp = await server.verifyPayment(payload, accepted!);
  expect(verifyResp.isValid, `${label}: verify failed: ${verifyResp.invalidReason}`).toBe(true);

  const settleResp = await server.settlePayment(payload, accepted!);
  expect(settleResp.success, `${label}: settle failed: ${settleResp.errorReason}`).toBe(true);
  console.log(`${label} ✅ tx=${settleResp.transaction}`);
  return settleResp;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

const skip = !env.FACILITATOR_PRIVATE_KEY;

describe.skipIf(skip)("EVM Wallet Compatibility Matrix — Base Sepolia", () => {
  let server: x402ResourceServer;
  let facilAcct: ReturnType<typeof privateKeyToAccount>;

  beforeAll(() => {
    const fixtures = buildExactServer(env.FACILITATOR_PRIVATE_KEY!);
    server = fixtures.server;
    facilAcct = fixtures.facilAcct;
  });

  // ════════════════════════════════════════════════════════════════════════════
  // Wallet A: Plain EOA
  // ════════════════════════════════════════════════════════════════════════════

  describe("Wallet A — Plain EOA", () => {
    it.skipIf(!env.CLIENT_PRIVATE_KEY)("exact / EIP-3009", { timeout: 60000 }, async () => {
      const acct = privateKeyToAccount(env.CLIENT_PRIVATE_KEY!);
      await runExactFlow(acct, buildExactEip3009Accepts(facilAcct.address), server, "A/EIP-3009");
    });

    it.skipIf(!env.CLIENT_PRIVATE_KEY)("exact / Permit2", { timeout: 60000 }, async () => {
      const acct = privateKeyToAccount(env.CLIENT_PRIVATE_KEY!);
      const { server: s, facilAcct: fa } = buildExactServer(env.FACILITATOR_PRIVATE_KEY!);
      await runExactFlow(acct, buildExactPermit2Accepts(fa.address), s, "A/Permit2");
    });

    it.skipIf(!env.CLIENT_PRIVATE_KEY)("upto / Permit2", { timeout: 60000 }, async () => {
      const acct = privateKeyToAccount(env.CLIENT_PRIVATE_KEY!);
      const accepts = buildUptoPermit2Accepts(facilAcct.address, facilAcct.address);
      await runUptoFlow(acct, accepts, env.FACILITATOR_PRIVATE_KEY!, "A/upto-Permit2");
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // Wallet B: Deployed ERC-4337-style smart account (SimpleWallet)
  // SimpleWallet has isValidSignature but NO execute function — cannot
  // create a Permit2 allowance. Only EIP-3009 is testable.
  // ════════════════════════════════════════════════════════════════════════════

  describe("Wallet B — Deployed smart account (EIP-1271)", () => {
    it.skipIf(!env.CLIENT_4337_ADDRESS || !env.CLIENT_4337_OWNER_PRIVATE_KEY)(
      "exact / EIP-3009 — USDC routes to isValidSignature, SimpleWallet accepts owner ECDSA",
      { timeout: 60000 },
      async () => {
        const ownerAcct = privateKeyToAccount(env.CLIENT_4337_OWNER_PRIVATE_KEY!);
        const fakeSmartAcct = { ...ownerAcct, address: getAddress(env.CLIENT_4337_ADDRESS!) };
        const settle = await runExactFlow(fakeSmartAcct as typeof ownerAcct, buildExactEip3009Accepts(facilAcct.address), server, "B/EIP-3009");
        expect(settle.payer.toLowerCase()).toBe(env.CLIENT_4337_ADDRESS!.toLowerCase());
      },
    );

    it.skipIf(!env.CLIENT_4337_ADDRESS)(
      "exact / Permit2 ❌ SKIPPED — SimpleWallet has no execute() to approve Permit2",
      () => {
        // On-chain Permit2 would accept the sig via isValidSignature (SimpleWallet has code),
        // but we can't pre-approve because SimpleWallet has no execute() function.
        // A real ERC-4337 account with UserOps capability would support this.
        // Covered as ✅ in the matrix doc with the note: requires smart account execution.
        console.log("B/Permit2: intentionally skipped — SimpleWallet cannot create a Permit2 allowance");
      },
    );
  });

  // ════════════════════════════════════════════════════════════════════════════
  // Wallet C: ERC-6492 counterfactual — fresh wallet every run
  // Generates a new private key and predicted address each test execution so
  // we always exercise the actual factory-deploy-then-transfer code path.
  // ════════════════════════════════════════════════════════════════════════════

  describe("Wallet C — ERC-6492 counterfactual (fresh wallet per run)", () => {
    it.skipIf(
      !env.CLIENT_6492_FACTORY || !env.CLIENT_PRIVATE_KEY,
    )(
      "exact / EIP-3009 — factory deploys wallet during settle, never pre-deployed",
      { timeout: 90000 },
      async () => {
        const pc = createPublicClient({ chain: baseSepolia, transport: http() });
        const funderAcct = privateKeyToAccount(env.CLIENT_PRIVATE_KEY!);
        const funderWc = createWalletClient({ account: funderAcct, chain: baseSepolia, transport: http() });

        // Fresh key + cryptographically random salt — unique per run, no collisions
        const freshOwnerKey = generatePrivateKey();
        const freshOwner = privateKeyToAccount(freshOwnerKey);
        const saltBytes = crypto.getRandomValues(new Uint8Array(32));
        const runSalt = ("0x" + Array.from(saltBytes).map(b => b.toString(16).padStart(2, "0")).join("")) as `0x${string}`;

        const factory = env.CLIENT_6492_FACTORY!;
        const predictedAddr = await factoryGetAddress(pc, factory, freshOwner.address, runSalt);

        // Sanity: must not be deployed yet (fresh salt)
        const code = await pc.getCode({ address: predictedAddr });
        expect(!code || code === "0x", "Fresh wallet must not be deployed").toBe(true);

        // Pre-fund the predicted address with USDC (from Wallet A funder)
        const fundHash = await funderWc.writeContract({
          address: USDC, abi: USDC_ABI, functionName: "transfer",
          args: [predictedAddr, BigInt(PAYMENT_AMOUNT)],
        });
        await pc.waitForTransactionReceipt({ hash: fundHash });
        console.log(`C: funded ${predictedAddr} with ${PAYMENT_AMOUNT} units USDC`);

        // Factory calldata to deploy SimpleWallet with freshOwner
        const factoryCalldata = encodeFunctionData({
          abi: FACTORY_ABI, functionName: "createWallet",
          args: [freshOwner.address, runSalt],
        });

        // Build payment payload: from = predictedAddr, signed by freshOwner key
        const fakeCounterfactualAcct = { ...freshOwner, address: predictedAddr };
        const { server: s6492 } = buildExactServer(
          env.FACILITATOR_PRIVATE_KEY!,
          [factory], // allowlist the factory
        );
        await s6492.initialize();

        const accepts6492 = buildExactEip3009Accepts(facilAcct.address);
        const evmClient = new ExactEvmClient(fakeCounterfactualAcct as typeof freshOwner);
        const client = new x402Client().register(NETWORK, evmClient);
        const paymentRequired = await s6492.createPaymentRequiredResponse(accepts6492, {
          url: "https://test.x402.org", description: "C/ERC-6492-fresh", mimeType: "application/json",
        });
        const innerPayload = await client.createPaymentPayload(paymentRequired);
        const innerSig = (innerPayload.payload as Record<string, unknown>).signature as `0x${string}`;

        // Verify from is the counterfactual address (not the signer's EOA)
        const innerAuth = (innerPayload.payload as Record<string, unknown>).authorization as Record<string, unknown>;
        expect(innerAuth.from.toString().toLowerCase()).toBe(predictedAddr.toLowerCase());

        // Wrap in ERC-6492
        const erc6492Sig = makeErc6492Sig(innerSig, factory, factoryCalldata);
        const erc6492Payload = {
          ...innerPayload,
          payload: { ...(innerPayload.payload as Record<string, unknown>), signature: erc6492Sig },
        };

        const accepted = s6492.findMatchingRequirements(accepts6492, erc6492Payload as never);
        expect(accepted).toBeDefined();

        // Verify: for undeployed wallet, returns false with sig_data (defer to settle)
        const verifyResp = await s6492.verifyPayment(erc6492Payload as never, accepted!);
        console.log(`C: verify isValid=${verifyResp.isValid} payer=${verifyResp.payer}`);

        // Settle: factory deploys wallet, then calls transferWithAuthorization
        const settleResp = await s6492.settlePayment(erc6492Payload as never, accepted!);
        console.log(`C/ERC-6492 settle: success=${settleResp.success} errorReason=${settleResp.errorReason} tx=${settleResp.transaction}`);
        expect(settleResp.success, `C/ERC-6492 settle failed: ${settleResp.errorReason}`).toBe(true);

        // Confirm wallet is now deployed
        const codeAfter = await pc.getCode({ address: predictedAddr });
        expect(codeAfter && codeAfter !== "0x", "Wallet must be deployed after settle").toBe(true);
        console.log(`C/ERC-6492 ✅ tx=${settleResp.transaction} — wallet deployed at ${predictedAddr}`);
      },
    );

    it("exact / Permit2 ❌ NOT SUPPORTED — Permit2 has no factory-deploy step", () => {
      // Permit2.permitWitnessTransferFrom calls isValidSignature at settlement time.
      // x402 does not deploy the factory before this call. An undeployed address has
      // no code, so isValidSignature reverts. Documented as ❌ in the matrix.
      console.log("C/Permit2: not supported — Permit2 cannot deploy factory before sig check");
    });

    it("upto / Permit2 ❌ NOT SUPPORTED — same reason as exact/Permit2", () => {
      console.log("C/upto-Permit2: not supported");
    });
  });

  // ════════════════════════════════════════════════════════════════════════════
  // Wallet D: ERC-7702 EOA delegated to PermissiveECDSADelegate
  // ════════════════════════════════════════════════════════════════════════════

  describe("Wallet D — ERC-7702 + permissive delegate", () => {
    it.skipIf(!env.CLIENT_7702_PRIVATE_KEY)(
      "exact / EIP-3009 — USDC routes to delegate's isValidSignature, delegate accepts owner ECDSA",
      { timeout: 60000 },
      async () => {
        const pc = createPublicClient({ chain: baseSepolia, transport: http() });
        const acct = privateKeyToAccount(env.CLIENT_7702_PRIVATE_KEY!);
        const code = await pc.getCode({ address: acct.address });
        if (!code?.startsWith("0xef0100")) {
          throw new Error(`Wallet D (${acct.address}) is not ERC-7702 delegated. Run setup-wallets-v3.mjs.`);
        }
        const settle = await runExactFlow(acct, buildExactEip3009Accepts(facilAcct.address), server, "D/EIP-3009");
        expect(settle.payer.toLowerCase()).toBe(acct.address.toLowerCase());
      },
    );

    it.skipIf(!env.CLIENT_7702_PRIVATE_KEY)(
      "exact / Permit2 — Permit2 routes to delegate.isValidSignature, delegate accepts owner ECDSA",
      { timeout: 60000 },
      async () => {
        const pc = createPublicClient({ chain: baseSepolia, transport: http() });
        const acct = privateKeyToAccount(env.CLIENT_7702_PRIVATE_KEY!);
        const code = await pc.getCode({ address: acct.address });
        if (!code?.startsWith("0xef0100")) throw new Error("Wallet D not delegated");

        // Ensure Permit2 allowance exists (7702 EOA can send approve txs normally)
        const acctWc = createWalletClient({ account: acct, chain: baseSepolia, transport: http() });
        const allowance = await pc.readContract({
          address: USDC, abi: USDC_ABI, functionName: "allowance", args: [acct.address, PERMIT2],
        });
        if (allowance < BigInt(PAYMENT_AMOUNT)) {
          const approveHash = await acctWc.writeContract({
            address: USDC, abi: USDC_ABI, functionName: "approve", args: [PERMIT2, maxUint256],
          });
          await pc.waitForTransactionReceipt({ hash: approveHash });
          console.log("D: approved Permit2");
        }

        const { server: sp2, facilAcct: fa } = buildExactServer(env.FACILITATOR_PRIVATE_KEY!);
        await runExactFlow(acct, buildExactPermit2Accepts(fa.address), sp2, "D/Permit2");
      },
    );

    it.skipIf(!env.CLIENT_7702_PRIVATE_KEY)(
      "upto / Permit2 — upto scheme with 7702-delegated payer",
      { timeout: 60000 },
      async () => {
        const pc = createPublicClient({ chain: baseSepolia, transport: http() });
        const acct = privateKeyToAccount(env.CLIENT_7702_PRIVATE_KEY!);
        const code = await pc.getCode({ address: acct.address });
        if (!code?.startsWith("0xef0100")) throw new Error("Wallet D not delegated");

        // Ensure allowance
        const acctWc = createWalletClient({ account: acct, chain: baseSepolia, transport: http() });
        const allowance = await pc.readContract({
          address: USDC, abi: USDC_ABI, functionName: "allowance", args: [acct.address, PERMIT2],
        });
        if (allowance < BigInt(PAYMENT_AMOUNT)) {
          const approveHash = await acctWc.writeContract({
            address: USDC, abi: USDC_ABI, functionName: "approve", args: [PERMIT2, maxUint256],
          });
          await pc.waitForTransactionReceipt({ hash: approveHash });
        }

        const accepts = buildUptoPermit2Accepts(facilAcct.address, facilAcct.address);
        await runUptoFlow(acct, accepts, env.FACILITATOR_PRIVATE_KEY!, "D/upto-Permit2");
      },
    );
  });
});
