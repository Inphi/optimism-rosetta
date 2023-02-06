// Copyright 2021 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package optimism

import (
	"context"
	"testing"

	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"
	"github.com/inphi/optimism-rosetta/optimism/utilities/artifacts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
)

const (
	OPContractAddress = "0xAA3aE75e8118FC1b6DeBC99Bc52dB28F7403A54c"
	OPSymbol          = "symbol"
	OPDecimals        = 18

	// emptySymbolDecimals = 0

	// blankSymbol                = ""
	// blankSymbolContractAddress = "0x6bd4e69abe087be7c09f094087d5c7f75b010abc"
	// blankSymbolDecimals        = 18

	invalidWETHContractAddress = "0x00dD3599Ae4813F3528C0d532851B937Cee1B489"
	invalidWETHSymbol          = "WETH"
	invalidWETHDecimals        = 0 // raw payload overflow

	// invalidContractAddressNonHex   = "0xdeadbeefdeadbeefdeadbeefdeadbeefzzzzzzzz"
	// invalidContractAddressTooShort = "0xdeadbeef"
	// invalidContractAddressMissingPrefix = "deadbeef"

	unknownContractAddress = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var OPCurrency = &RosettaTypes.Currency{
	Symbol:   OPSymbol,
	Decimals: int32(OPDecimals),
	Metadata: map[string]interface{}{
		ContractAddressKey: OPContractAddress,
	},
}

// var blankSymbolCurrency = &RosettaTypes.Currency{
// 	Symbol:   defaultERC20Symbol,
// 	Decimals: int32(blankSymbolDecimals),
// 	Metadata: map[string]interface{}{
// 		ContractAddressKey: blankSymbolContractAddress,
// 	},
// }

var unknownCurrency = &RosettaTypes.Currency{
	Symbol:   defaultERC20Symbol,
	Decimals: int32(defaultERC20Decimals),
	Metadata: map[string]interface{}{
		ContractAddressKey: unknownContractAddress,
	},
}

var invalidWETHCurrency = &RosettaTypes.Currency{
	Symbol:   invalidWETHSymbol,
	Decimals: int32(invalidWETHDecimals),
	Metadata: map[string]interface{}{
		ContractAddressKey: invalidWETHContractAddress,
	},
}

func erc20ABIPack(method string) string {
	data, err := artifacts.ERC20ABI.Pack(method)
	if err != nil {
		panic(err)
	}
	return hexutil.Encode(data)
}

var encodedDecimalsData = erc20ABIPack("decimals")
var encodedSymbolData = erc20ABIPack("symbol")

func mockCalls(
	t *testing.T,
	mockJSONRPC *mocks.JSONRPC,
	contractAddress string,
	blockNum uint64,
	decimals string,
	symbol string,
) {
	ctx := context.Background()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 2 && rpcs[0].Method == "eth_call" && rpcs[1].Method == "eth_call"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			blockNumHex := hexutil.EncodeUint64(blockNum)

			r := args.Get(1).([]rpc.BatchElem)
			assert.Len(t, r, 2)
			assert.Equal(t, r[0].Args[0], map[string]string{"to": contractAddress, "data": encodedDecimalsData})
			assert.Equal(t, r[0].Args[1], blockNumHex)
			assert.Equal(t, r[1].Args[0], map[string]string{"to": contractAddress, "data": encodedSymbolData})
			assert.Equal(t, r[1].Args[1], blockNumHex)

			// encodedDecimals, _ := rlp.EncodeToBytes(decimals)
			*(r[0].Result.(*string)) = decimals
			*(r[1].Result.(*string)) = symbol
		},
	).Once()
}

func TestFetchCurrency(t *testing.T) {
	var tests = map[string]struct {
		contractAddress  string
		expectedCurrency *RosettaTypes.Currency
		decimals         int
		symbol           string
		mockFn           func(mockJSONRPC *mocks.JSONRPC, contractAddress string, blockNum uint64)
		error            error
	}{
		"happy path: valid contract address": {
			contractAddress:  OPContractAddress,
			expectedCurrency: OPCurrency,
			decimals:         OPDecimals,
			symbol:           OPSymbol,
			mockFn: func(mockJSONRPC *mocks.JSONRPC, contractAddress string, blockNum uint64) {
				decimals := "0x0000000000000000000000000000000000000000000000000000000000000012"                                                                                                                               // 18
				symbol := "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000673796d626f6c0000000000000000000000000000000000000000000000000000" // symbol
				mockCalls(t, mockJSONRPC, contractAddress, blockNum, decimals, symbol)
			},
			error: nil,
		},
		"happy path: invalid currency details parsed as unknownCurrency": {
			contractAddress:  unknownContractAddress,
			expectedCurrency: unknownCurrency,
			decimals:         defaultERC20Decimals,
			symbol:           defaultERC20Symbol,
			mockFn: func(mockJSONRPC *mocks.JSONRPC, contractAddress string, blockNum uint64) {
				mockCalls(t, mockJSONRPC, contractAddress, blockNum, "0x", "0x")
			},
			error: nil,
		},
		"happy path: overflow (> int32) token decimals parsed as 0": {
			contractAddress:  invalidWETHContractAddress,
			expectedCurrency: invalidWETHCurrency,
			decimals:         invalidWETHDecimals,
			symbol:           invalidWETHSymbol,
			mockFn: func(mockJSONRPC *mocks.JSONRPC, contractAddress string, blockNum uint64) {
				mockCalls(t, mockJSONRPC, contractAddress, blockNum, "0x00000000000000000000000000000000000000000000021e19e0c9bab2400000", "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000045745544800000000000000000000000000000000000000000000000000000000")
			},
			error: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			mockJSONRPC := &mocks.JSONRPC{}

			cf, err := newERC20CurrencyFetcher(mockJSONRPC)
			assert.NoError(t, err)

			var blockNum uint64 = 1
			test.mockFn(mockJSONRPC, test.contractAddress, blockNum)

			fetchedCurrency, err := cf.FetchCurrency(ctx, blockNum, test.contractAddress)
			assert.Equal(t, test.expectedCurrency, fetchedCurrency)
			assert.Equal(t, test.error, err)

			mockJSONRPC.AssertExpectations(t)

			// Currencies for which we were able to successfully fetch details should be cached,
			// such that subsequent queries are not needed (hence we don't need to re-mock)
			if test.error == nil {
				fetchedCurrency, err = cf.FetchCurrency(ctx, blockNum, test.contractAddress)
				assert.Equal(t, test.expectedCurrency, fetchedCurrency)
				assert.NoError(t, err)

				mockJSONRPC.AssertExpectations(t)
			}
		})
	}
}
