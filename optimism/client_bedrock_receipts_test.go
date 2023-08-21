// Copyright 2023 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package optimism

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	L2GethTypes "github.com/ethereum-optimism/optimism/l2geth/core/types"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthHexutil "github.com/ethereum/go-ethereum/common/hexutil"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sync/semaphore"
)

type ClientBedrockReceiptsTestSuite struct {
	suite.Suite

	mockJSONRPC         *mocks.JSONRPC
	mockGraphQL         *mocks.GraphQL
	mockCurrencyFetcher *mocks.CurrencyFetcher
	client              *Client
}

func TestClientBedrockReceipts(t *testing.T) {
	suite.Run(t, new(ClientBedrockReceiptsTestSuite))
}

func (testSuite *ClientBedrockReceiptsTestSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
	testSuite.mockCurrencyFetcher = &mocks.CurrencyFetcher{}
	testSuite.client = &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		traceSemaphore:  semaphore.NewWeighted(100),
	}
}

// TestExtractL1Fee tests extracting the L1 fee from a transaction.
func (testSuite *ClientBedrockReceiptsTestSuite) TestExtractL1Fee() {
	// Read the L1 fee from the receipt
	file, err := os.ReadFile("testdata/goerli_bedrock_tx_receipt_5003318_2.json")
	testSuite.NoError(err)
	readTxReceipt := json.RawMessage(file)
	var receipt L2GethTypes.Receipt
	err = json.Unmarshal(readTxReceipt, &receipt)
	testSuite.Nil(err)

	// Extract the fee and validate
	l1Fee := ExtractL1Fee(&RosettaTxReceipt{
		Type:           2,
		GasPrice:       convertBigInt("0x4ee2f"),
		GasUsed:        convertBigInt("0x4a853"),
		TransactionFee: convertBigInt("0x1585ba2a8"),
		Logs:           []*EthTypes.Log{},
		RawMessage:     readTxReceipt,
	})
	testSuite.Equal(convertBigInt("0x1585ba2a8"), l1Fee)
}

// TestGetBlockReceipts tests fetching bedrock block receipts from the op client.
func (testSuite *ClientBedrockReceiptsTestSuite) TestGetBlockReceipts() {
	// Construct arguments
	ctx := context.Background()
	hash := EthCommon.HexToHash("0xb358c6958b1cab722752939cbb92e3fec6b6023de360305910ce80c56c3dad9d")
	gasPrice := big.NewInt(10000)
	blockNumber := big.NewInt(1)
	blockNumberString := blockNumber.String()
	to := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
	nonce := uint64(0)
	myTx := &transaction{
		Nonce:     (*EthHexutil.Uint64)(&nonce),
		Recipient: &to,
		Value:     (*EthHexutil.Big)(big.NewInt(0)),
		GasLimit:  (EthHexutil.Uint64)(0),
		Price:     (*EthHexutil.Big)(gasPrice),
		Data:      (*EthHexutil.Bytes)(nil),
	}
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
		receipt := arg[0].Result.(*json.RawMessage)
		rawReceipt, _ := ethReceipt.MarshalJSON()
		*receipt = json.RawMessage(rawReceipt)
		arg[0].Error = nil
	})

	return ethReceipt
}
