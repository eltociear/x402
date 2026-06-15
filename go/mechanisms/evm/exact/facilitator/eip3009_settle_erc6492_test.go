package facilitator

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	"github.com/x402-foundation/x402/go/v2/types"
)

// settleMockSigner is a minimal FacilitatorEvmSigner for the ERC-6492 settle path.
// ReadContract errors on transferWithAuthorization (the post-deploy transfer simulation)
// to model a deployed wallet that rejects the inner signature; GetCode reports the payer
// as undeployed and the asset as a deployed contract.
type settleMockSigner struct {
	codeByAddress map[string][]byte
}

func (m *settleMockSigner) GetAddresses() []string { return []string{"0xFac11"} }

func (m *settleMockSigner) ReadContract(ctx context.Context, address string, abi []byte, functionName string, args ...interface{}) (interface{}, error) {
	if functionName == "transferWithAuthorization" {
		return nil, fmt.Errorf("execution reverted: invalid signature")
	}
	return nil, nil
}

func (m *settleMockSigner) VerifyTypedData(ctx context.Context, address string, domain evm.TypedDataDomain, types map[string][]evm.TypedDataField, primaryType string, message map[string]interface{}, signature []byte) (bool, error) {
	return false, nil
}

func (m *settleMockSigner) WriteContract(ctx context.Context, address string, abi []byte, functionName string, args ...interface{}) (string, error) {
	return "0x" + strings.Repeat("ab", 32), nil
}

func (m *settleMockSigner) SendTransaction(ctx context.Context, to string, data []byte) (string, error) {
	return "0x" + strings.Repeat("cd", 32), nil
}

func (m *settleMockSigner) WaitForTransactionReceipt(ctx context.Context, txHash string) (*evm.TransactionReceipt, error) {
	return &evm.TransactionReceipt{Status: evm.TxStatusSuccess, TxHash: txHash}, nil
}

func (m *settleMockSigner) GetBalance(ctx context.Context, address string, tokenAddress string) (*big.Int, error) {
	return big.NewInt(1_000_000_000), nil
}

func (m *settleMockSigner) GetChainID(ctx context.Context) (*big.Int, error) {
	return big.NewInt(84532), nil
}

func (m *settleMockSigner) GetCode(ctx context.Context, address string) ([]byte, error) {
	return m.codeByAddress[strings.ToLower(address)], nil
}

// When the ERC-6492 factory deploys the wallet but the deployed wallet rejects the inner
// signature (post-deploy transfer simulation reverts), settle must return the retry-guidance
// error rather than submitting a doomed transfer.
func TestSettleEIP3009_DeployedWalletRejectsInnerSig(t *testing.T) {
	const (
		// factory address baked into wrapERC6492Signature
		factory = "0xca11bde05977b3631167028862be2a173976ca11"
		payer   = "0x1234567890123456789012345678901234567890"
		payTo   = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0"
		token   = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
	)

	innerSig := common.FromHex("0x" + strings.Repeat("33", 66))
	wrapped := wrapERC6492Signature(t, innerSig)

	p := &evm.ExactEIP3009Payload{
		Signature: "0x" + common.Bytes2Hex(wrapped),
		Authorization: evm.ExactEIP3009Authorization{
			From:        payer,
			To:          payTo,
			Value:       "1000000",
			ValidAfter:  "0",
			ValidBefore: "99999999999",
			Nonce:       "0x" + strings.Repeat("00", 32),
		},
	}

	requirements := types.PaymentRequirements{
		Scheme:  "exact",
		Network: "eip155:84532",
		Amount:  "1000000",
		Asset:   token,
		PayTo:   payTo,
		Extra:   map[string]interface{}{"name": "USDC", "version": "2"},
	}
	payload := types.PaymentPayload{
		X402Version: 2,
		Payload:     p.ToMap(),
		Accepted:    requirements,
	}

	signer := &settleMockSigner{
		codeByAddress: map[string][]byte{
			strings.ToLower(token): {0x60, 0x60}, // asset is a deployed contract
			strings.ToLower(payer): {},           // payer is undeployed (counterfactual)
		},
	}
	scheme := NewExactEvmScheme(signer, &ExactEvmSchemeConfig{
		EIP6492AllowedFactories: []string{factory},
	})

	resp, err := scheme.Settle(context.Background(), payload, requirements, nil)
	if err == nil {
		t.Fatalf("expected settle error, got success: %+v", resp)
	}

	se := &x402.SettleError{}
	if !errors.As(err, &se) {
		t.Fatalf("expected *x402.SettleError, got %T: %v", err, err)
	}
	if se.ErrorReason != ErrDeployedInnerWalletSignatureUnsupported {
		t.Fatalf("expected reason %q, got %q", ErrDeployedInnerWalletSignatureUnsupported, se.ErrorReason)
	}
	if se.ErrorMessage != MsgDeployedInnerWalletSignatureUnsupported {
		t.Fatalf("expected retry-guidance message, got %q", se.ErrorMessage)
	}
}
