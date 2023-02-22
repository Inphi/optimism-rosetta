package optimism

import (
	"math/big"
	"testing"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	EthCommon "github.com/ethereum/go-ethereum/common"
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

// TestInvalidDeposit tests that a non-deposit tx is not handled by MintOps.
func (testSuite *BedrockOpsTestSuite) TestInvalidDeposit() {
	// Construct a random transaction (non-DepositTx)
	txHash := EthCommon.HexToHash("0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d")
	gasPrice := big.NewInt(10000)

	innerTx := NewBedrockTransaction(
		0,
		EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87"),
		big.NewInt(0),
		0,
		gasPrice,
		nil,
	)
	from := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
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
	innerTx := NewTransactionFromFields(
		convertBigInt("0x7e").Uint64(),      // type
		0,                                   // nonce
		gasPrice,                            // gasPrice
		nil,                                 // maxPriorityFee
		nil,                                 // maxFee
		convertBigInt("0x8f0d180").Uint64(), // gasLim
		amount,                              // value
		[]byte{},                            // data
		nil,                                 // v
		nil,                                 // r
		nil,                                 // s
		recipient,                           // to
		nil,                                 // chain
		txHash,                              // hash
	)
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
			Type:   MintOpType,
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
