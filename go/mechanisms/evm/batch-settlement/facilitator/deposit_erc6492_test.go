package facilitator

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	batchsettlement "github.com/x402-foundation/x402/go/v2/mechanisms/evm/batch-settlement"
	"github.com/x402-foundation/x402/go/v2/types"
)

const (
	testErc6492Factory = "0xca11bde05977b3631167028862be2a173976ca11"
)

// wrapErc6492Sig wraps innerSig in the ERC-6492 envelope with the given factory + calldata.
func wrapErc6492Sig(t *testing.T, factory common.Address, factoryCalldata, innerSig []byte) string {
	t.Helper()
	addressTy, err := abi.NewType("address", "", nil)
	if err != nil {
		t.Fatalf("abi address type: %v", err)
	}
	bytesTy, err := abi.NewType("bytes", "", nil)
	if err != nil {
		t.Fatalf("abi bytes type: %v", err)
	}
	args := abi.Arguments{{Type: addressTy}, {Type: bytesTy}, {Type: bytesTy}}
	packed, err := args.Pack(factory, factoryCalldata, innerSig)
	if err != nil {
		t.Fatalf("pack erc6492: %v", err)
	}
	magic := common.Hex2Bytes("6492649264926492649264926492649264926492649264926492649264926492")
	return "0x" + common.Bytes2Hex(append(packed, magic...))
}

func counterfactualAuth(t *testing.T, factory common.Address) *batchsettlement.BatchSettlementErc3009Authorization {
	t.Helper()
	auth := goodErc3009Auth()
	inner := common.FromHex("0x" + strings.Repeat("33", 65))
	auth.Signature = wrapErc6492Sig(t, factory, common.FromHex("0xdeadbeef"), inner)
	return auth
}

// TestVerifyErc3009_CounterfactualFactoryNotAllowed pins that an undeployed ERC-6492
// wallet whose factory is not allowlisted is rejected with ErrFactoryNotAllowed.
func TestVerifyErc3009_CounterfactualFactoryNotAllowed(t *testing.T) {
	signer := &fakeFacilitatorSigner{
		getCode: func(string) ([]byte, error) { return nil, nil }, // undeployed
	}
	sigData, reason, err := verifyErc3009DepositAuthorization(
		context.Background(), signer,
		goodErc3009Config(), testErc3009ChannelId,
		big.NewInt(1000), counterfactualAuth(t, common.HexToAddress(testErc6492Factory)),
		big.NewInt(8453), goodErc3009Extra(),
		nil, // empty allowlist
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if reason != ErrFactoryNotAllowed {
		t.Fatalf("reason = %q, want %q", reason, ErrFactoryNotAllowed)
	}
	if sigData != nil {
		t.Fatalf("expected nil sigData on rejection, got %+v", sigData)
	}
}

// TestVerifyErc3009_CounterfactualAllowedDefersToSimulation pins that an undeployed
// ERC-6492 wallet with an allowlisted factory returns a non-nil sigData (signalling the
// caller to validate via the deploy+deposit simulation) and no rejection reason.
func TestVerifyErc3009_CounterfactualAllowedDefersToSimulation(t *testing.T) {
	signer := &fakeFacilitatorSigner{
		getCode: func(string) ([]byte, error) { return nil, nil }, // undeployed
	}
	sigData, reason, err := verifyErc3009DepositAuthorization(
		context.Background(), signer,
		goodErc3009Config(), testErc3009ChannelId,
		big.NewInt(1000), counterfactualAuth(t, common.HexToAddress(testErc6492Factory)),
		big.NewInt(8453), goodErc3009Extra(),
		[]string{testErc6492Factory},
	)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty (deferred to simulation)", reason)
	}
	if sigData == nil || !evm.HasEIP6492Deployment(sigData) {
		t.Fatalf("expected non-nil sigData with deployment info, got %+v", sigData)
	}
}

// counterfactualDepositPayload builds a deposit payload from an undeployed ERC-6492 wallet.
func counterfactualDepositPayload(t *testing.T, factory common.Address) *batchsettlement.BatchSettlementDepositPayload {
	t.Helper()
	return &batchsettlement.BatchSettlementDepositPayload{
		Type:          "deposit",
		ChannelConfig: goodErc3009Config(),
		Voucher: batchsettlement.BatchSettlementVoucherFields{
			ChannelId:          testErc3009ChannelId,
			MaxClaimableAmount: "1000",
			Signature:          "0x" + strings.Repeat("22", 65),
		},
		Deposit: batchsettlement.BatchSettlementDepositData{
			Amount: "1000",
			Authorization: batchsettlement.BatchSettlementDepositAuthorization{
				Erc3009Authorization: counterfactualAuth(t, factory),
			},
		},
	}
}

func reqsWithExtra() types.PaymentRequirements {
	return types.PaymentRequirements{
		Scheme:  batchsettlement.SchemeBatched,
		Network: testNetwork,
		Asset:   testErc3009Token,
		Extra:   goodErc3009Extra(),
	}
}

// TestSettleDeposit_CounterfactualFactoryNotAllowed pins that settle rejects an undeployed
// ERC-6492 deposit whose factory is not in the allowlist — before sending any transaction.
func TestSettleDeposit_CounterfactualFactoryNotAllowed(t *testing.T) {
	signer := &fakeFacilitatorSigner{
		getCode: func(string) ([]byte, error) { return nil, nil }, // undeployed
	}
	payload := counterfactualDepositPayload(t, common.HexToAddress(testErc6492Factory))
	configTuple := ToContractChannelConfig(payload.ChannelConfig)
	collectorData, err := batchsettlement.BuildErc3009CollectorData(
		payload.Deposit.Authorization.Erc3009Authorization.ValidAfter,
		payload.Deposit.Authorization.Erc3009Authorization.ValidBefore,
		payload.Deposit.Authorization.Erc3009Authorization.Salt,
		payload.Deposit.Authorization.Erc3009Authorization.Signature,
	)
	if err != nil {
		t.Fatalf("collector data: %v", err)
	}
	collectorAddr := common.HexToAddress(batchsettlement.ERC3009DepositCollectorAddress)

	resp, err := deployErc3009CounterfactualIfNeeded(
		context.Background(), signer, payload, reqsWithExtra(), nil, // empty allowlist
		configTuple, big.NewInt(1000), collectorAddr, collectorData,
	)
	if resp != nil {
		t.Fatalf("expected nil response, got %+v", resp)
	}
	var se *x402.SettleError
	if !errors.As(err, &se) || se.ErrorReason != ErrFactoryNotAllowed {
		t.Fatalf("got err = %v, want %s", err, ErrFactoryNotAllowed)
	}
	if signer.sendCalls != 0 {
		t.Fatalf("expected no deploy tx for disallowed factory, sendCalls=%d", signer.sendCalls)
	}
}

// TestSettleDeposit_CounterfactualDeployedWalletRejectsInnerSig pins that after the factory
// deploys the wallet, a deposit simulation revert (lazily-installed validator) surfaces the
// retry-guidance error instead of submitting a doomed deposit.
func TestSettleDeposit_CounterfactualDeployedWalletRejectsInnerSig(t *testing.T) {
	signer := &fakeFacilitatorSigner{
		getCode:         func(string) ([]byte, error) { return nil, nil }, // undeployed
		sendTransaction: func(string, []byte) (string, error) { return "0x" + strings.Repeat("ab", 32), nil },
		waitForReceipt: func(txHash string) (*evm.TransactionReceipt, error) {
			return &evm.TransactionReceipt{Status: evm.TxStatusSuccess, TxHash: txHash}, nil
		},
		// Post-deploy deposit simulation reverts → deployed wallet rejects the inner sig.
		readContract: func(fn string, _ ...interface{}) (interface{}, error) {
			if fn == "deposit" {
				return nil, errors.New("execution reverted: invalid signature")
			}
			return nil, nil
		},
	}
	payload := counterfactualDepositPayload(t, common.HexToAddress(testErc6492Factory))
	configTuple := ToContractChannelConfig(payload.ChannelConfig)
	collectorData, err := batchsettlement.BuildErc3009CollectorData(
		payload.Deposit.Authorization.Erc3009Authorization.ValidAfter,
		payload.Deposit.Authorization.Erc3009Authorization.ValidBefore,
		payload.Deposit.Authorization.Erc3009Authorization.Salt,
		payload.Deposit.Authorization.Erc3009Authorization.Signature,
	)
	if err != nil {
		t.Fatalf("collector data: %v", err)
	}
	collectorAddr := common.HexToAddress(batchsettlement.ERC3009DepositCollectorAddress)

	resp, err := deployErc3009CounterfactualIfNeeded(
		context.Background(), signer, payload, reqsWithExtra(), []string{testErc6492Factory},
		configTuple, big.NewInt(1000), collectorAddr, collectorData,
	)
	if resp != nil {
		t.Fatalf("expected nil response, got %+v", resp)
	}
	var se *x402.SettleError
	if !errors.As(err, &se) || se.ErrorReason != ErrDeployedInnerWalletSignatureUnsupported {
		t.Fatalf("got err = %v, want %s", err, ErrDeployedInnerWalletSignatureUnsupported)
	}
	if se.ErrorMessage != MsgDeployedInnerWalletSignatureUnsupported {
		t.Fatalf("got message %q, want retry-guidance message", se.ErrorMessage)
	}
	if signer.sendCalls != 1 {
		t.Fatalf("expected exactly one deploy tx, sendCalls=%d", signer.sendCalls)
	}
	if signer.writeCalls != 0 {
		t.Fatalf("expected no deposit tx submitted, writeCalls=%d", signer.writeCalls)
	}
}

// TestSettleDeposit_CounterfactualHappyPath pins that an allowlisted, deployable wallet whose
// post-deploy deposit simulation succeeds returns (nil, nil) so settle proceeds to deposit.
func TestSettleDeposit_CounterfactualHappyPath(t *testing.T) {
	signer := &fakeFacilitatorSigner{
		getCode:         func(string) ([]byte, error) { return nil, nil }, // undeployed
		sendTransaction: func(string, []byte) (string, error) { return "0x" + strings.Repeat("ab", 32), nil },
		waitForReceipt: func(txHash string) (*evm.TransactionReceipt, error) {
			return &evm.TransactionReceipt{Status: evm.TxStatusSuccess, TxHash: txHash}, nil
		},
		readContract: func(fn string, _ ...interface{}) (interface{}, error) {
			return nil, nil // deposit simulation succeeds
		},
	}
	payload := counterfactualDepositPayload(t, common.HexToAddress(testErc6492Factory))
	configTuple := ToContractChannelConfig(payload.ChannelConfig)
	collectorData, _ := batchsettlement.BuildErc3009CollectorData(
		payload.Deposit.Authorization.Erc3009Authorization.ValidAfter,
		payload.Deposit.Authorization.Erc3009Authorization.ValidBefore,
		payload.Deposit.Authorization.Erc3009Authorization.Salt,
		payload.Deposit.Authorization.Erc3009Authorization.Signature,
	)
	collectorAddr := common.HexToAddress(batchsettlement.ERC3009DepositCollectorAddress)

	resp, err := deployErc3009CounterfactualIfNeeded(
		context.Background(), signer, payload, reqsWithExtra(), []string{testErc6492Factory},
		configTuple, big.NewInt(1000), collectorAddr, collectorData,
	)
	if err != nil || resp != nil {
		t.Fatalf("expected (nil, nil) to proceed to deposit, got resp=%+v err=%v", resp, err)
	}
	if signer.sendCalls != 1 {
		t.Fatalf("expected one deploy tx, sendCalls=%d", signer.sendCalls)
	}
}

// TestSettleDeposit_PlainSigNoDeploy pins that a non-wrapped (plain EOA) signature triggers
// no deployment path: deployErc3009CounterfactualIfNeeded is a no-op.
func TestSettleDeposit_PlainSigNoDeploy(t *testing.T) {
	signer := &fakeFacilitatorSigner{}
	payload := counterfactualDepositPayload(t, common.HexToAddress(testErc6492Factory))
	// Replace the wrapped signature with a plain 65-byte signature.
	payload.Deposit.Authorization.Erc3009Authorization.Signature = "0x" + strings.Repeat("11", 65)

	resp, err := deployErc3009CounterfactualIfNeeded(
		context.Background(), signer, payload, reqsWithExtra(), []string{testErc6492Factory},
		ToContractChannelConfig(payload.ChannelConfig), big.NewInt(1000),
		common.HexToAddress(batchsettlement.ERC3009DepositCollectorAddress), []byte{0x01},
	)
	if err != nil || resp != nil {
		t.Fatalf("expected no-op (nil, nil) for plain sig, got resp=%+v err=%v", resp, err)
	}
	if signer.sendCalls != 0 {
		t.Fatalf("expected no deploy tx for plain sig, sendCalls=%d", signer.sendCalls)
	}
}
