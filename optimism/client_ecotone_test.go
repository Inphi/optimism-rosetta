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

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	EthCommon "github.com/ethereum/go-ethereum/common"
	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sync/semaphore"
)

type ClientEcotoneTestSuite struct {
	suite.Suite

	mockJSONRPC         *mocks.JSONRPC
	mockGraphQL         *mocks.GraphQL
	mockCurrencyFetcher *mocks.CurrencyFetcher
}

func (t *ClientEcotoneTestSuite) MockJSONRPC() *mocks.JSONRPC {
	return t.mockJSONRPC
}

func TestClientEcotone(t *testing.T) {
	suite.Run(t, new(ClientEcotoneTestSuite))
}

func (testSuite *ClientEcotoneTestSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
	testSuite.mockCurrencyFetcher = &mocks.CurrencyFetcher{}
}

func (testSuite *ClientEcotoneTestSuite) TestEcotoneBlock() {
	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		tc:              testBedrockTraceConfig,
		p:               params.TestnetChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
		filterTokens:    false,
		bedrockBlock:    big.NewInt(0),
	}

	ctx := context.Background()
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := os.ReadFile("testdata/sepolia_ecotone_block_4089330.json")
			testSuite.NoError(err)
			*r = json.RawMessage(file)
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		[]interface{}{"latest", true},
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := os.ReadFile("testdata/sepolia_ecotone_block_4089330.json")
			testSuite.NoError(err)
			*r = json.RawMessage(file)
		},
	).Once()

	tx1 := EthCommon.HexToHash("0xd62fb327dc8df4e8f6a1ad70c9ff03099d2f85c75b9d943d5d6885e62be31069")

	// Execute the transaction trace
	mockTraceTransaction(ctx, testSuite, "testdata/sepolia_ecotone_tx_trace_5003318_1.json")
	mockGetEcotoneTransactionReceipt(ctx, testSuite, []EthCommon.Hash{tx1}, []string{"testdata/sepolia_ecotone_tx_receipt_4089330_1.json"})

	correctRaw, err := os.ReadFile("testdata/sepolia_ecotone_block_response_4089330.json")
	testSuite.NoError(err)
	var correct *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correct))

	// Fetch the latest block and validate
	resp, err := c.Block(ctx, nil)
	testSuite.NoError(err)
	testSuite.Equal(correct.Block, resp)
}

func mockGetEcotoneTransactionReceipt(ctx context.Context, testSuite *ClientEcotoneTestSuite, txhashes []EthCommon.Hash, txFileData []string) {
	testSuite.Equal(len(txhashes), len(txFileData))
	numReceipts := len(txhashes)
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == numReceipts && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)
			testSuite.Len(r, numReceipts)
			for i := range txhashes {
				testSuite.Equal(
					txhashes[i].Hex(),
					r[i].Args[0],
				)
				file, err := os.ReadFile(txFileData[i])
				testSuite.NoError(err)
				*(r[i].Result.(*json.RawMessage)) = json.RawMessage(file)
			}
		},
	).Once()
}
