package optimism

import (
	"math/big"
	"testing"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthHexutil "github.com/ethereum/go-ethereum/common/hexutil"
	EthTypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/stretchr/testify/suite"
)

// BedrockOpsTestSuite is a test suite for bedrock rosetta operation construction.
type BedrockOpsTestSuite struct {
	suite.Suite
}

// TestBedrockOps runs the BedrockOpsTestSuite.
func TestBedrockOps(t *testing.T) {
	suite.Run(t, new(BedrockOpsTestSuite))
}

// TestNoFeeOpsForDepositTx tests that no fee operations are constructed for deposit transactions.
func (testSuite *BedrockOpsTestSuite) TestNoFeeOpsForDepositTx() {
	// Deposit Transactions should have no fee operations.
	txHash := EthCommon.HexToHash("0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d")
	gasPrice := big.NewInt(10000)
	nonce := uint64(0)
	to := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
	from := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
	innerTx := &transaction{
		Type:      L1ToL2DepositType,
		Nonce:     (*EthHexutil.Uint64)(&nonce),
		Recipient: &to,
		Value:     (*EthHexutil.Big)(big.NewInt(0)),
		GasLimit:  (EthHexutil.Uint64)(0),
		Price:     (*EthHexutil.Big)(gasPrice),
		Data:      (*EthHexutil.Bytes)(nil),
	}
	bedrockTransaction := bedrockTransaction{
		Transaction: innerTx,
		From:        &from,
		BlockHash:   &EthTypes.EmptyRootHash,
		TxHash:      &txHash,
		FeeAmount:   big.NewInt(0),
		Miner:       "095e7baea6a6c7c4c2dfeb977efac326af552d87",
	}
	operations, err := FeeOps(&bedrockTransaction)
	testSuite.NoError(err)
	testSuite.Len(operations, 0)
}

// TestInvalidDeposit tests that a non-deposit tx is not handled by MintOps.
func (testSuite *BedrockOpsTestSuite) TestInvalidDeposit() {
	// Construct a random transaction (non-DepositTx)
	txHash := EthCommon.HexToHash("0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d")
	gasPrice := big.NewInt(10000)
	nonce := uint64(0)
	to := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
	from := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
	innerTx := &transaction{
		Nonce:     (*EthHexutil.Uint64)(&nonce),
		Recipient: &to,
		Value:     (*EthHexutil.Big)(big.NewInt(0)),
		GasLimit:  (EthHexutil.Uint64)(0),
		Price:     (*EthHexutil.Big)(gasPrice),
		Data:      (*EthHexutil.Bytes)(nil),
	}
	bedrockTx := bedrockTransaction{
		Transaction: innerTx,
		From:        &from,
		BlockHash:   &EthTypes.EmptyRootHash,
		TxHash:      &txHash,
		FeeAmount:   big.NewInt(0),
		Miner:       "095e7baea6a6c7c4c2dfeb977efac326af552d87",
	}

	// MintOps should return nil for non-min transactions.
	ops := MintOps(&bedrockTx, 0)
	testSuite.Nil(ops)
}

// TestValidMint tests [MintOps] correctly constructs a [RosettaTypes.Operation],
// with a provided Mint transaction.
func (testSuite *BedrockOpsTestSuite) TestValidMint() {
	// Construct a loaded mint transaction.
	txHash := EthCommon.HexToHash("0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d")
	gasPrice := big.NewInt(10000)
	amount := big.NewInt(100)
	index := 1
	from := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
	recipient := EthCommon.HexToAddress("0x4200000000000000000000000000000000000015")
	nonce := uint64(0)
	innerTx := &transaction{
		Type:                 (EthHexutil.Uint64)(convertBigInt("0x7e").Uint64()),
		Nonce:                (*EthHexutil.Uint64)(&nonce),
		Price:                (*EthHexutil.Big)(gasPrice),
		MaxPriorityFeePerGas: (*EthHexutil.Big)(nil),
		MaxFeePerGas:         (*EthHexutil.Big)(nil),
		GasLimit:             (EthHexutil.Uint64)(convertBigInt("0x8f0d180").Uint64()),
		Value:                (*EthHexutil.Big)(amount),
		Data:                 (*EthHexutil.Bytes)(&[]byte{}),
		V:                    (*EthHexutil.Big)(nil),
		R:                    (*EthHexutil.Big)(nil),
		S:                    (*EthHexutil.Big)(nil),
		Recipient:            &recipient,
		ChainID:              (*EthHexutil.Big)(nil),
		HashValue:            txHash,
	}
	bedrockTx := bedrockTransaction{
		Transaction: innerTx,
		From:        &from,
		BlockHash:   &EthTypes.EmptyRootHash,
		TxHash:      &txHash,
		FeeAmount:   big.NewInt(0),
		Miner:       "095e7baea6a6c7c4c2dfeb977efac326af552d87",
	}

	// MintOps should successfully construct a Mint operation.
	ops := MintOps(&bedrockTx, index)
	testSuite.Equal(ops, []*RosettaTypes.Operation{
		{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: int64(index),
			},
			Type:   CallOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: from.String(),
			},
			Amount: Amount(amount, Currency),
		},
	})
}

// TestValidTrace tests [TraceOps] correctly constructs [RosettaTypes.Operation]s.
func (testSuite *BedrockOpsTestSuite) TestValidTrace() {
	index := 1
	amount := big.NewInt(100)
	gasUsed := big.NewInt(10000)
	from := EthCommon.HexToAddress("0x1234")
	to := EthCommon.HexToAddress("0x4566")

	calls := []*FlatCall{
		{
			Type:         CallOpType,
			From:         from,
			To:           to,
			Value:        amount,
			GasUsed:      gasUsed,
			Revert:       false,
			ErrorMessage: "",
		},
	}

	// Validate the constructed trace operations
	ops := TraceOps(calls, index)
	testSuite.Equal([]*RosettaTypes.Operation{
		{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: int64(index),
			},
			Type:   CallOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: from.String(),
			},
			Amount: &RosettaTypes.Amount{
				Value:    "-100",
				Currency: Currency,
			},
			Metadata: map[string]interface{}{},
		},
		{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: int64(index + 1),
			},
			Type:   CallOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: to.String(),
			},
			RelatedOperations: []*RosettaTypes.OperationIdentifier{
				{
					Index: int64(index),
				},
			},
			Amount:   Amount(amount, Currency),
			Metadata: map[string]interface{}{},
		},
	}, ops)
}
