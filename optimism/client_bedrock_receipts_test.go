package optimism

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ClientBedrockReceiptsTestSuite struct {
	suite.Suite

	mockJSONRPC         *mocks.JSONRPC
	mockGraphQL         *mocks.GraphQL
	mockCurrencyFetcher *mocks.CurrencyFetcher
}

func TestClientBedrockReceipts(t *testing.T) {
	suite.Run(t, new(ClientBedrockReceiptsTestSuite))
}

func (testSuite *ClientBedrockReceiptsTestSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
	testSuite.mockCurrencyFetcher = &mocks.CurrencyFetcher{}
}

// TestGetBlockReceipts tests fetching bedrock block receipts from the op client.
func (testSuite *ClientBlocksTestSuite) TestGetBlockReceipts() {
	// Construct arguments
	ctx := context.Background()
	hash := EthCommon.HexToHash("0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d")
	gasPrice := big.NewInt(10000)
	blockNumber := big.NewInt(1)
	blockNumberString := blockNumber.String()
	to := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
	myTx := NewBedrockTransaction(
		0,
		to,
		big.NewInt(0),
		0,
		gasPrice,
		nil,
	)
	txs := []BedrockRPCTransaction{
		{
			Tx: myTx,
			TxExtraInfo: TxExtraInfo{
				BlockNumber: &blockNumberString,
				BlockHash:   &hash,
				From:        &to,
				TxHash:      &hash,
			},
		},
	}
	baseFee := big.NewInt(10000)

	// Mock the internall call to the mock client
	ethReceipt := mockBedrockReceipt(testSuite.mockJSONRPC)

	// Perform internal calculations
	gasPrice, _ = EffectiveGasPrice(myTx, baseFee)
	gasUsed := new(big.Int).SetUint64(ethReceipt.GasUsed)
	feeAmount := new(big.Int).Mul(gasUsed, gasPrice)
	receiptJSON, _ := ethReceipt.MarshalJSON()
	receipt := &RosettaTxReceipt{
		Type:           ethReceipt.Type,
		GasPrice:       gasPrice,
		GasUsed:        gasUsed,
		Logs:           ethReceipt.Logs,
		RawMessage:     receiptJSON,
		TransactionFee: feeAmount,
	}

	// Execute and validate the call
	txReceipts, err := testSuite.client.getBedrockBlockReceipts(ctx, hash, txs, baseFee)
	testSuite.NoError(err)
	testSuite.Equal([]*RosettaTxReceipt{receipt}, txReceipts)
}

func mockBedrockReceipt(mocker *mocks.JSONRPC) EthTypes.Receipt {
	ctx := context.Background()
	hash := EthCommon.HexToHash("0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d")
	blockNumber := big.NewInt(1)
	to := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
	ethReceipt := EthTypes.Receipt{
		// Consensus fields: These fields are defined by the Yellow Paper
		Type:              0,
		PostState:         []byte{0x00},
		Status:            1,
		CumulativeGasUsed: 0,
		Bloom:             EthTypes.BytesToBloom([]byte{0x00}),
		Logs:              []*EthTypes.Log{},
		// Implementation fields: These fields are added by geth when processing a transaction.
		// They are stored in the chain database.
		TxHash:          hash,
		ContractAddress: to,
		GasUsed:         0,
		// transaction corresponding to this receipt.
		BlockHash:        hash,
		BlockNumber:      blockNumber,
		TransactionIndex: 0,
		// OVM legacy: extend receipts with their L1 price (if a rollup tx)
		// IGNORED
	}
	mocker.On("BatchCallContext", ctx, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		arg := args.Get(1).([]rpc.BatchElem)
		receipt := arg[0].Result.(**EthTypes.Receipt)
		*receipt = &ethReceipt
		// arg[0].Result = ethReceipt
		arg[0].Error = nil
	})

	return ethReceipt
}
