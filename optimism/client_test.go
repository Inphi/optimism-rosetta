// Copyright 2020 Coinbase, Inc.
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
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"

	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/common/hexutil"

	l2gethTypes "github.com/ethereum-optimism/optimism/l2geth/core/types"
	"github.com/ethereum-optimism/optimism/l2geth/eth"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sync/semaphore"
)

var account = "0x2f93B2f047E05cdf602820Ac4B3178efc2b43D55"

func TestCall_GetBlockByNumber(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x2af0",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*map[string]interface{})

			file, err := os.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)

			err = json.Unmarshal(file, r)
			assert.NoError(t, err)
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_10992.json")
	assert.NoError(t, err)
	var correct map[string]interface{}
	assert.NoError(t, json.Unmarshal(correctRaw, &correct))

	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_getBlockByNumber",
			Parameters: map[string]interface{}{
				"index":                    RosettaTypes.Int64(10992),
				"show_transaction_details": false,
			},
		},
	)
	assert.Equal(t, &RosettaTypes.CallResponse{
		Result:     correct,
		Idempotent: false,
	}, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestCall_GetBlockByNumber_InvalidArgs(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_getBlockByNumber",
			Parameters: map[string]interface{}{
				"index":                    "a string",
				"show_transaction_details": false,
			},
		},
	)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrCallParametersInvalid))

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestCall_GetTransactionReceipt(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getTransactionReceipt",
		common.HexToHash("0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a"),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(**l2gethTypes.Receipt)

			file, err := os.ReadFile(
				"testdata/tx_receipt_1.json",
			)
			assert.NoError(t, err)

			*r = new(l2gethTypes.Receipt)

			assert.NoError(t, (*r).UnmarshalJSON(file))
		},
	).Once()
	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_getTransactionReceipt",
			Parameters: map[string]interface{}{
				"tx_hash": "0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a",
			},
		},
	)
	assert.NoError(t, err)

	file, err := os.ReadFile("testdata/tx_receipt_1.json")
	assert.NoError(t, err)
	var receiptMap map[string]interface{}
	assert.NoError(t, json.Unmarshal(file, &receiptMap))

	// set null fields
	receiptMap["root"] = "0x"
	receiptMap["contractAddress"] = "0x0000000000000000000000000000000000000000"
	delete(receiptMap, "from")
	delete(receiptMap, "to")

	assert.Equal(t, &RosettaTypes.CallResponse{
		Result:     receiptMap,
		Idempotent: false,
	}, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestCall_GetTransactionReceipt_InvalidArgs(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_getTransactionReceipt",
		},
	)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrCallParametersInvalid))

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestCall_Call(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_call",
		map[string]string{
			"to":   "0xB5E5D0F8C0cbA267CD3D7035d6AdC8eBA7Df7Cdd",
			"data": "0x70a08231000000000000000000000000b5e5d0f8c0cba267cd3d7035d6adc8eba7df7cdd",
		},
		toBlockNumArg(big.NewInt(11408349)),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*string)

			var expected map[string]interface{}
			file, err := os.ReadFile("testdata/call_balance_11408349.json")
			assert.NoError(t, err)

			err = json.Unmarshal(file, &expected)
			assert.NoError(t, err)

			*r = expected["data"].(string)
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/call_balance_11408349.json")
	assert.NoError(t, err)
	var correct map[string]interface{}
	assert.NoError(t, json.Unmarshal(correctRaw, &correct))

	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_call",
			Parameters: map[string]interface{}{
				"index": 11408349,
				"to":    "0xB5E5D0F8C0cbA267CD3D7035d6AdC8eBA7Df7Cdd",
				"data":  "0x70a08231000000000000000000000000b5e5d0f8c0cba267cd3d7035d6adc8eba7df7cdd",
			},
		},
	)
	assert.Equal(t, &RosettaTypes.CallResponse{
		Result:     correct,
		Idempotent: false,
	}, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestCall_Call_InvalidArgs(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_call",
			Parameters: map[string]interface{}{
				"index": 11408349,
				"Hash":  "0x73fc065bc04f16c98247f8ec1e990f581ec58723bcd8059de85f93ab18706448",
				"to":    "not valid  ",
				"data":  "0x70a08231000000000000000000000000b5e5d0f8c0cba267cd3d7035d6adc8eba7df7cdd",
			},
		},
	)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrCallParametersInvalid))

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestCall_EstimateGas(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_estimateGas",
		map[string]string{
			"from": "0xE550f300E477C60CE7e7172d12e5a27e9379D2e3",
			"to":   "0xaD6D458402F60fD3Bd25163575031ACDce07538D",
			"data": "0xa9059cbb000000000000000000000000ae7e48ee0f758cd706b76cf7e2175d982800879a" +
				"00000000000000000000000000000000000000000000000000521c5f98b8ea00",
		},
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*string)

			var expected map[string]interface{}
			file, err := os.ReadFile("testdata/estimate_gas_0xaD6D458402F60fD3Bd25163575031ACDce07538D.json")
			assert.NoError(t, err)

			err = json.Unmarshal(file, &expected)
			assert.NoError(t, err)

			*r = expected["data"].(string)
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/estimate_gas_0xaD6D458402F60fD3Bd25163575031ACDce07538D.json")
	assert.NoError(t, err)
	var correct map[string]interface{}
	assert.NoError(t, json.Unmarshal(correctRaw, &correct))

	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_estimateGas",
			Parameters: map[string]interface{}{
				"from": "0xE550f300E477C60CE7e7172d12e5a27e9379D2e3",
				"to":   "0xaD6D458402F60fD3Bd25163575031ACDce07538D",
				"data": "0xa9059cbb000000000000000000000000ae7e48ee0f758cd706b76cf7e2175d982800879a" +
					"00000000000000000000000000000000000000000000000000521c5f98b8ea00",
			},
		},
	)
	assert.Equal(t, &RosettaTypes.CallResponse{
		Result:     correct,
		Idempotent: false,
	}, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestCall_EstimateGas_InvalidArgs(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "eth_estimateGas",
			Parameters: map[string]interface{}{
				"From": "0xE550f300E477C60CE7e7172d12e5a27e9379D2e3",
				"to":   "0xaD6D458402F60fD3Bd25163575031ACDce07538D",
			},
		},
	)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrCallParametersInvalid))

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestCall_InvalidMethod(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	resp, err := c.Call(
		ctx,
		&RosettaTypes.CallRequest{
			Method: "blah",
		},
	)
	assert.Nil(t, resp)
	assert.True(t, errors.Is(err, ErrCallMethodInvalid))

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func testTraceConfig() (*eth.TraceConfig, error) {
	loadedFile, err := os.ReadFile("call_tracer.js")
	if err != nil {
		return nil, fmt.Errorf("%w: could not load tracer file", err)
	}

	loadedTracer := string(loadedFile)
	tracerTimeout := "120s"
	return &eth.TraceConfig{
		Timeout: &tracerTimeout,
		Tracer:  &loadedTracer,
	}, nil
}

func TestBlock_Current(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	tc, err := testTraceConfig()
	assert.NoError(t, err)
	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
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

			file, err := os.ReadFile("testdata/block_1.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "debug_traceTransaction"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Len(t, r[0].Args, 2)
			assert.Equal(
				t,
				common.HexToHash("0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a").Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_1.json",
			)
			assert.NoError(t, err)

			call := new(Call)
			assert.NoError(t, call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Equal(
				t,
				"0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_1.json",
			)
			assert.NoError(t, err)

			receipt := new(l2gethTypes.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**l2gethTypes.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_1.json")
	assert.NoError(t, err)
	var correct *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correct))

	resp, err := c.Block(
		ctx,
		nil,
	)
	assert.Equal(t, correct.Block, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestBlock_Hash(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	tc, err := testTraceConfig()
	assert.NoError(t, err)
	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByHash",
		"0xbee7192e575af30420cae0c7776304ac196077ee72b048970549e4f08e875453",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_1.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "debug_traceTransaction"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Len(t, r[0].Args, 2)
			assert.Equal(
				t,
				common.HexToHash("0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a").Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_1.json",
			)
			assert.NoError(t, err)

			call := new(Call)
			assert.NoError(t, call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Equal(
				t,
				"0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_1.json",
			)
			assert.NoError(t, err)

			receipt := new(l2gethTypes.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**l2gethTypes.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_1.json")
	assert.NoError(t, err)
	var correct *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correct))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Hash: RosettaTypes.String(
				"0xbee7192e575af30420cae0c7776304ac196077ee72b048970549e4f08e875453",
			),
		},
	)
	assert.Equal(t, correct.Block, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func jsonifyBlock(b *RosettaTypes.Block) (*RosettaTypes.Block, error) {
	bytes, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}

	var bo RosettaTypes.Block
	if err := json.Unmarshal(bytes, &bo); err != nil {
		return nil, err
	}

	return &bo, nil
}

func TestBlock_Index(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	tc, err := testTraceConfig()
	assert.NoError(t, err)
	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.MainnetChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x1",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_1.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "debug_traceTransaction"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Len(t, r[0].Args, 2)
			assert.Equal(
				t,
				common.HexToHash("0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a").Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_1.json",
			)
			assert.NoError(t, err)

			call := new(Call)
			assert.NoError(t, call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Equal(
				t,
				"0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_1.json",
			)
			assert.NoError(t, err)

			receipt := new(l2gethTypes.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**l2gethTypes.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_1.json")
	assert.NoError(t, err)
	var correctResp *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(1),
		},
	)
	assert.Equal(t, correctResp.Block, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

// Block with duplicate transaction bug
func TestBlock_985(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	tc, err := testTraceConfig()
	assert.NoError(t, err)
	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x3d9",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_985.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "debug_traceTransaction"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Len(t, r[0].Args, 2)
			assert.Equal(
				t,
				common.HexToHash("0x9ed8f713b2cc6439657db52dcd2fdb9cc944915428f3c6e2a7703e242b259cb9").Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_985.json",
			)
			assert.NoError(t, err)

			call := new(Call)
			assert.NoError(t, call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Equal(
				t,
				"0x9ed8f713b2cc6439657db52dcd2fdb9cc944915428f3c6e2a7703e242b259cb9",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_0x9ed8f713b2cc6439657db52dcd2fdb9cc944915428f3c6e2a7703e242b259cb9.json",
			) // nolint
			assert.NoError(t, err)

			receipt := new(l2gethTypes.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**l2gethTypes.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_985.json")
	assert.NoError(t, err)
	var correctResp *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(985),
		},
	)
	assert.NoError(t, err)

	// Ensure types match
	jsonResp, err := jsonifyBlock(resp)
	assert.NoError(t, err)
	assert.Equal(t, correctResp.Block, jsonResp)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

// Block with tx send to non-whitelisted contract
func TestBlock_87673(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	tc, err := testTraceConfig()
	assert.NoError(t, err)
	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x15679",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_87673.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "debug_traceTransaction"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Len(t, r[0].Args, 2)
			assert.Equal(
				t,
				common.HexToHash("0xcf6e46a1f41e1678fba10590f9d092690c5e8fd2e85a3614715fb21caa74655d").Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_87673.json",
			)
			assert.NoError(t, err)

			call := new(Call)
			assert.NoError(t, call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Equal(
				t,
				"0xcf6e46a1f41e1678fba10590f9d092690c5e8fd2e85a3614715fb21caa74655d",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_0xcf6e46a1f41e1678fba10590f9d092690c5e8fd2e85a3614715fb21caa74655d.json",
			) // nolint
			assert.NoError(t, err)

			receipt := new(l2gethTypes.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**l2gethTypes.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_87673.json")
	assert.NoError(t, err)
	var correctResp *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(87673),
		},
	)
	assert.NoError(t, err)

	// Ensure types match
	jsonResp, err := jsonifyBlock(resp)
	assert.NoError(t, err)
	assert.Equal(t, correctResp.Block, jsonResp)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

// Block with L2 deposit
func TestBlock_22698(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	tc, err := testTraceConfig()
	assert.NoError(t, err)
	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x58aa",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_22698.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "debug_traceTransaction"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Len(t, r[0].Args, 2)
			assert.Equal(
				t,
				common.HexToHash("0xe58efba2da474da0cd5d32d4a9781629fb832391bc9d8897879790843225b1a9").Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_22698.json",
			)
			assert.NoError(t, err)

			call := new(Call)
			assert.NoError(t, call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Equal(
				t,
				"0xe58efba2da474da0cd5d32d4a9781629fb832391bc9d8897879790843225b1a9",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_0xe58efba2da474da0cd5d32d4a9781629fb832391bc9d8897879790843225b1a9.json",
			) // nolint
			assert.NoError(t, err)

			receipt := new(l2gethTypes.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**l2gethTypes.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_22698.json")
	assert.NoError(t, err)
	var correctResp *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(22698),
		},
	)
	assert.NoError(t, err)

	// Ensure types match
	jsonResp, err := jsonifyBlock(resp)
	assert.NoError(t, err)
	assert.Equal(t, correctResp.Block, jsonResp)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

// Block with L2 OPTETH withdraw
func TestBlock_985465(t *testing.T) { // updated
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	tc, err := testTraceConfig()
	assert.NoError(t, err)
	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0xf0979", // updated
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_985465.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "debug_traceTransaction"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Len(t, r[0].Args, 2)
			assert.Equal(
				t,
				common.HexToHash("0x4ee3a15e4ff6c8e8c6ff64c6a2e74ebce90eccb2e479d7488f5bb070727a3e5c").Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_985465.json",
			)
			assert.NoError(t, err)

			call := new(Call)
			assert.NoError(t, call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 1)
			assert.Equal(
				t,
				"0x4ee3a15e4ff6c8e8c6ff64c6a2e74ebce90eccb2e479d7488f5bb070727a3e5c",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_0x4ee3a15e4ff6c8e8c6ff64c6a2e74ebce90eccb2e479d7488f5bb070727a3e5c.json",
			) // nolint
			assert.NoError(t, err)

			receipt := new(l2gethTypes.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**l2gethTypes.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_985465.json")
	assert.NoError(t, err)
	var correctResp *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(985465),
		},
	)
	assert.NoError(t, err)

	// Ensure types match
	jsonResp, err := jsonifyBlock(resp)
	assert.NoError(t, err)
	assert.Equal(t, correctResp.Block, jsonResp)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestPendingNonceAt(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getTransactionCount",
		common.HexToAddress("0xfFC614eE978630D7fB0C06758DeB580c152154d3"),
		"pending",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*hexutil.Uint64)

			*r = hexutil.Uint64(10)
		},
	).Once()
	resp, err := c.PendingNonceAt(
		ctx,
		common.HexToAddress("0xfFC614eE978630D7fB0C06758DeB580c152154d3"),
	)
	assert.Equal(t, uint64(10), resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestSuggestGasPrice(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_gasPrice",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*hexutil.Big)

			*r = *(*hexutil.Big)(big.NewInt(100000))
		},
	).Once()
	resp, err := c.SuggestGasPrice(
		ctx,
	)
	assert.Equal(t, big.NewInt(100000), resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestSendTransaction(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_sendRawTransaction",
		"0xf86a80843b9aca00825208941ff502f9fe838cd772874cb67d0d96b93fd1d6d78725d4b6199a415d8029a01d110bf9fd468f7d00b3ce530832e99818835f45e9b08c66f8d9722264bb36c7a02711f47ec99f9ac585840daef41b7118b52ec72f02fcb30d874d36b10b668b59", // nolint
	).Return(
		nil,
	).Once()

	rawTx, err := os.ReadFile("testdata/submitted_tx.json")
	assert.NoError(t, err)

	tx := new(types.Transaction)
	assert.NoError(t, tx.UnmarshalJSON(rawTx))

	assert.NoError(t, c.SendTransaction(
		ctx,
		tx,
	))

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}
