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
	"io/ioutil"
	"math/big"
	"strconv"
	"testing"

	mocks "github.com/coinbase/rosetta-ethereum/mocks/optimism"
	"github.com/coinbase/rosetta-ethereum/optimism/utilities/artifacts"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	"github.com/ethereum-optimism/optimism/l2geth/core/types"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sync/semaphore"
)

func TestStatus_NotReady(t *testing.T) {
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
		"latest",
		false,
	).Return(
		nil,
	).Once()

	block, timestamp, syncStatus, peers, err := c.Status(ctx)
	assert.Nil(t, block)
	assert.Equal(t, int64(-1), timestamp)
	assert.Nil(t, syncStatus)
	assert.Nil(t, peers)
	assert.True(t, errors.Is(err, ethereum.NotFound))

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestStatus_NotSyncing(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}

	c := &Client{
		c:              mockJSONRPC,
		g:              mockGraphQL,
		traceSemaphore: semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			header := args.Get(1).(**types.Header)
			file, err := ioutil.ReadFile("testdata/basic_header.json")
			assert.NoError(t, err)

			*header = new(types.Header)

			assert.NoError(t, (*header).UnmarshalJSON(file))
		},
	).Once()

	block, timestamp, syncStatus, peers, err := c.Status(ctx)
	assert.Equal(t, &RosettaTypes.BlockIdentifier{
		Hash:  "0x48269a339ce1489cff6bab70eff432289c4f490b81dbd00ff1f81c68de06b842",
		Index: 8916656,
	}, block)
	assert.Equal(t, int64(1603225195000), timestamp)
	assert.Equal(t, &RosettaTypes.SyncStatus{
		CurrentIndex: RosettaTypes.Int64(8916656),
		TargetIndex:  RosettaTypes.Int64(8916656),
	}, syncStatus)
	assert.Nil(t, peers)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestStatus_NotSyncing_SkipAdminCalls(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}

	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
		skipAdminCalls:  true,
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			header := args.Get(1).(**types.Header)
			file, err := ioutil.ReadFile("testdata/basic_header.json")
			assert.NoError(t, err)

			*header = new(types.Header)

			assert.NoError(t, (*header).UnmarshalJSON(file))
		},
	).Once()

	adminPeersSkipped := true

	block, timestamp, syncStatus, peers, err := c.Status(ctx)
	assert.True(t, adminPeersSkipped)
	assert.Equal(t, &RosettaTypes.BlockIdentifier{
		Hash:  "0x48269a339ce1489cff6bab70eff432289c4f490b81dbd00ff1f81c68de06b842",
		Index: 8916656,
	}, block)
	assert.Equal(t, int64(1603225195000), timestamp)
	assert.Equal(t, &RosettaTypes.SyncStatus{
		CurrentIndex: RosettaTypes.Int64(8916656),
		TargetIndex:  RosettaTypes.Int64(8916656),
	}, syncStatus)
	assert.Nil(t, peers)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestStatus_Syncing(t *testing.T) {
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
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			header := args.Get(1).(**types.Header)
			file, err := ioutil.ReadFile("testdata/basic_header.json")
			assert.NoError(t, err)

			*header = new(types.Header)

			assert.NoError(t, (*header).UnmarshalJSON(file))
		},
	).Once()

	block, timestamp, syncStatus, peers, err := c.Status(ctx)
	assert.Equal(t, &RosettaTypes.BlockIdentifier{
		Hash:  "0x48269a339ce1489cff6bab70eff432289c4f490b81dbd00ff1f81c68de06b842",
		Index: 8916656,
	}, block)
	assert.Equal(t, int64(1603225195000), timestamp)
	assert.Equal(t, &RosettaTypes.SyncStatus{
		CurrentIndex: RosettaTypes.Int64(8916656),
		TargetIndex:  RosettaTypes.Int64(8916656),
	}, syncStatus)
	assert.Nil(t, peers)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestStatus_Syncing_SkipAdminCalls(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(mockJSONRPC)
	assert.NoError(t, err)

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
		skipAdminCalls:  true,
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			header := args.Get(1).(**types.Header)
			file, err := ioutil.ReadFile("testdata/basic_header.json")
			assert.NoError(t, err)

			*header = new(types.Header)

			assert.NoError(t, (*header).UnmarshalJSON(file))
		},
	).Once()

	adminPeersSkipped := true

	block, timestamp, syncStatus, peers, err := c.Status(ctx)
	assert.True(t, adminPeersSkipped)
	assert.Equal(t, &RosettaTypes.BlockIdentifier{
		Hash:  "0x48269a339ce1489cff6bab70eff432289c4f490b81dbd00ff1f81c68de06b842",
		Index: 8916656,
	}, block)
	assert.Equal(t, int64(1603225195000), timestamp)
	assert.Equal(t, &RosettaTypes.SyncStatus{
		CurrentIndex: RosettaTypes.Int64(8916656),
		TargetIndex:  RosettaTypes.Int64(8916656),
	}, syncStatus)
	assert.Nil(t, peers)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestBalance(t *testing.T) {
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
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()

	blockNum := fmt.Sprintf("0x%s", strconv.FormatInt(10992, 16))
	account := "0x2f93B2f047E05cdf602820Ac4B3178efc2b43D55"
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 3 && rpcs[0].Method == "eth_getBalance" && rpcs[1].Method == "eth_getTransactionCount" && rpcs[2].Method == "eth_getCode"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 3)
			for i := range r {
				assert.Len(t, r[i].Args, 2)
				assert.Equal(t, r[i].Args[0], account)
				assert.Equal(t, r[i].Args[1], blockNum)
			}

			balance := hexutil.MustDecodeBig("0x2324c0d180077fe7000")
			*(r[0].Result.(*hexutil.Big)) = (hexutil.Big)(*balance)
			*(r[1].Result.(*hexutil.Uint64)) = hexutil.Uint64(0)
			*(r[2].Result.(*string)) = "0x"
		},
	).Once()

	callData, err := artifacts.ERC20ABI.Pack("balanceOf", common.HexToAddress(account))
	assert.NoError(t, err)
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_call",
		map[string]string{
			"data": fmt.Sprintf("0x%s", common.Bytes2Hex(callData)),
			"to":   opTokenContractAddress.String(),
		},
		blockNum,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*string)
			var expected map[string]interface{}
			file, err := ioutil.ReadFile("testdata/call_balance_token_10992.json")
			assert.NoError(t, err)

			err = json.Unmarshal(file, &expected)
			assert.NoError(t, err)

			*r = expected["data"].(string)
		},
	).Once()

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: "0x2f93B2f047E05cdf602820Ac4B3178efc2b43D55",
		},
		nil,
		nil,
	)
	assert.Equal(t, &RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  "0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
			Index: 10992,
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "10372550232136640000000",
				Currency: Currency,
			},
			{
				Value:    "1000000000000000000000",
				Currency: OPTokenCurrency,
			},
		},
		Metadata: map[string]interface{}{
			"code":  "0x",
			"nonce": int64(0),
		},
	}, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
}

func TestBalance_Historical_Hash(t *testing.T) {
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
	account := "0x2f93B2f047E05cdf602820Ac4B3178efc2b43D55"
	blockNum := fmt.Sprintf("0x%s", strconv.FormatInt(10992, 16))

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByHash",
		mock.Anything,
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			blockHash := *args.Get(3).(*string)
			assert.Equal(t, "0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae", blockHash)

			r := args.Get(1).(*json.RawMessage)
			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)
			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 3 && rpcs[0].Method == "eth_getBalance" && rpcs[1].Method == "eth_getTransactionCount" && rpcs[2].Method == "eth_getCode"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 3)
			for i := range r {
				assert.Len(t, r[i].Args, 2)
				assert.Equal(t, r[i].Args[0], account)
				assert.Equal(t, r[i].Args[1], blockNum)
			}

			balance := hexutil.MustDecodeBig("0x2324c0d180077fe7000")
			*(r[0].Result.(*hexutil.Big)) = (hexutil.Big)(*balance)
			*(r[1].Result.(*hexutil.Uint64)) = hexutil.Uint64(0)
			*(r[2].Result.(*string)) = "0x"
		},
	).Once()

	callData, err := artifacts.ERC20ABI.Pack("balanceOf", common.HexToAddress(account))
	assert.NoError(t, err)
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_call",
		map[string]string{
			"data": fmt.Sprintf("0x%s", common.Bytes2Hex(callData)),
			"to":   opTokenContractAddress.String(),
		},
		blockNum,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*string)
			var expected map[string]interface{}
			file, err := ioutil.ReadFile("testdata/call_balance_token_10992.json")
			assert.NoError(t, err)

			err = json.Unmarshal(file, &expected)
			assert.NoError(t, err)

			*r = expected["data"].(string)
		},
	).Once()

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: account,
		},
		&RosettaTypes.PartialBlockIdentifier{
			Hash: RosettaTypes.String(
				"0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
			),
			Index: RosettaTypes.Int64(8165),
		},
		nil,
	)
	assert.Equal(t, &RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  "0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
			Index: 10992,
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "10372550232136640000000",
				Currency: Currency,
			},
			{
				Value:    "1000000000000000000000",
				Currency: OPTokenCurrency,
			},
		},
		Metadata: map[string]interface{}{
			"code":  "0x",
			"nonce": int64(0),
		},
	}, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestBalance_Historical_Index(t *testing.T) {
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
	account := "0x2f93B2f047E05cdf602820Ac4B3178efc2b43D55"
	blockNum := fmt.Sprintf("0x%s", strconv.FormatInt(10992, 16))

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		blockNum,
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)
			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 3 && rpcs[0].Method == "eth_getBalance" && rpcs[1].Method == "eth_getTransactionCount" && rpcs[2].Method == "eth_getCode"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			assert.Len(t, r, 3)
			for i := range r {
				assert.Len(t, r[i].Args, 2)
				assert.Equal(t, r[i].Args[0], account)
				assert.Equal(t, r[i].Args[1], blockNum)
			}

			balance := hexutil.MustDecodeBig("0x2324c0d180077fe7000")
			*(r[0].Result.(*hexutil.Big)) = (hexutil.Big)(*balance)
			*(r[1].Result.(*hexutil.Uint64)) = hexutil.Uint64(0)
			*(r[2].Result.(*string)) = "0x"
		},
	).Once()

	callData, err := artifacts.ERC20ABI.Pack("balanceOf", common.HexToAddress(account))
	assert.NoError(t, err)
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_call",
		map[string]string{
			"data": fmt.Sprintf("0x%s", common.Bytes2Hex(callData)),
			"to":   opTokenContractAddress.String(),
		},
		blockNum,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*string)
			var expected map[string]interface{}
			file, err := ioutil.ReadFile("testdata/call_balance_token_10992.json")
			assert.NoError(t, err)

			err = json.Unmarshal(file, &expected)
			assert.NoError(t, err)

			*r = expected["data"].(string)
		},
	).Once()

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: account,
		},
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(10992),
		},
		nil,
	)
	assert.Equal(t, &RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  "0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
			Index: 10992,
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "10372550232136640000000",
				Currency: Currency,
			},
			{
				Value:    "1000000000000000000000",
				Currency: OPTokenCurrency,
			},
		},
		Metadata: map[string]interface{}{
			"code":  "0x",
			"nonce": int64(0),
		},
	}, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestBalance_InvalidAddress(t *testing.T) {
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
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 3 && rpcs[0].Method == "eth_getBalance" && rpcs[1].Method == "eth_getTransactionCount" && rpcs[2].Method == "eth_getCode"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)
			assert.Len(t, r, 3)
			r[0].Error = fmt.Errorf("invalid argument 0")
		},
	).Once()

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: "0x4cfc400fed52f9681b42454c2db4b18ab98f8de",
		},
		nil,
		nil,
	)
	assert.Nil(t, resp)
	assert.Error(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

func TestBalance_InvalidHash(t *testing.T) {
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
	invalidHash := "0x7d2a2713026a0e66f131878de2bb2df2fff6c24562c1df61ec0265e5fedf2626"

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByHash",
		mock.Anything,
		false,
	).Return(
		fmt.Errorf("invalid argument"),
	).Run(
		func(args mock.Arguments) {
			blockHash := *args.Get(3).(*string)
			assert.Equal(t, invalidHash, blockHash)
		},
	).Once()

	resp, err := c.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: "0x2f93B2f047E05cdf602820Ac4B3178efc2b43D55",
		},
		&RosettaTypes.PartialBlockIdentifier{
			Hash: RosettaTypes.String(
				invalidHash,
			),
		},
		nil,
	)
	assert.Nil(t, resp)
	assert.Error(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}

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

			file, err := ioutil.ReadFile("testdata/block_10992.json")
			assert.NoError(t, err)

			err = json.Unmarshal(file, r)
			assert.NoError(t, err)
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_10992.json")
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
			r := args.Get(1).(**types.Receipt)

			file, err := ioutil.ReadFile(
				"testdata/tx_receipt_1.json",
			)
			assert.NoError(t, err)

			*r = new(types.Receipt)

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

	file, err := ioutil.ReadFile("testdata/tx_receipt_1.json")
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
			file, err := ioutil.ReadFile("testdata/call_balance_11408349.json")
			assert.NoError(t, err)

			err = json.Unmarshal(file, &expected)
			assert.NoError(t, err)

			*r = expected["data"].(string)
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/call_balance_11408349.json")
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
			file, err := ioutil.ReadFile("testdata/estimate_gas_0xaD6D458402F60fD3Bd25163575031ACDce07538D.json")
			assert.NoError(t, err)

			err = json.Unmarshal(file, &expected)
			assert.NoError(t, err)

			*r = expected["data"].(string)
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/estimate_gas_0xaD6D458402F60fD3Bd25163575031ACDce07538D.json")
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

func testTraceConfig() (*tracers.TraceConfig, error) {
	loadedFile, err := ioutil.ReadFile("call_tracer.js")
	if err != nil {
		return nil, fmt.Errorf("%w: could not load tracer file", err)
	}

	loadedTracer := string(loadedFile)
	tracerTimeout := "120s"
	return &tracers.TraceConfig{
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

			file, err := ioutil.ReadFile("testdata/block_1.json")
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

			file, err := ioutil.ReadFile(
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

			file, err := ioutil.ReadFile(
				"testdata/tx_receipt_1.json",
			)
			assert.NoError(t, err)

			receipt := new(types.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_1.json")
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

			file, err := ioutil.ReadFile("testdata/block_1.json")
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

			file, err := ioutil.ReadFile(
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

			file, err := ioutil.ReadFile(
				"testdata/tx_receipt_1.json",
			)
			assert.NoError(t, err)

			receipt := new(types.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_1.json")
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

			file, err := ioutil.ReadFile("testdata/block_1.json")
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

			file, err := ioutil.ReadFile(
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

			file, err := ioutil.ReadFile(
				"testdata/tx_receipt_1.json",
			)
			assert.NoError(t, err)

			receipt := new(types.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_1.json")
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

			file, err := ioutil.ReadFile("testdata/block_985.json")
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

			file, err := ioutil.ReadFile(
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

			file, err := ioutil.ReadFile(
				"testdata/tx_receipt_0x9ed8f713b2cc6439657db52dcd2fdb9cc944915428f3c6e2a7703e242b259cb9.json",
			) // nolint
			assert.NoError(t, err)

			receipt := new(types.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_985.json")
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

			file, err := ioutil.ReadFile("testdata/block_87673.json")
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

			file, err := ioutil.ReadFile(
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

			file, err := ioutil.ReadFile(
				"testdata/tx_receipt_0xcf6e46a1f41e1678fba10590f9d092690c5e8fd2e85a3614715fb21caa74655d.json",
			) // nolint
			assert.NoError(t, err)

			receipt := new(types.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_87673.json")
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

			file, err := ioutil.ReadFile("testdata/block_22698.json")
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

			file, err := ioutil.ReadFile(
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

			file, err := ioutil.ReadFile(
				"testdata/tx_receipt_0xe58efba2da474da0cd5d32d4a9781629fb832391bc9d8897879790843225b1a9.json",
			) // nolint
			assert.NoError(t, err)

			receipt := new(types.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_22698.json")
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

	rawTx, err := ioutil.ReadFile("testdata/submitted_tx.json")
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

func TestBlock_ERC20Mint(t *testing.T) {
	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	mockCurrencyFetcher := &mocks.CurrencyFetcher{}

	tc, err := testTraceConfig()
	assert.NoError(t, err)
	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: mockCurrencyFetcher,
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
		"0x12f062",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := ioutil.ReadFile("testdata/block_1241186.json")
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
				common.HexToHash("0xd919fe87c4bc24f767d1b7a165266658d542af9e3f9bc11dd1a2d1f4695df009").Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, tc, r[0].Args[1])

			file, err := ioutil.ReadFile(
				"testdata/tx_trace_1241186.json",
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
				"0xd919fe87c4bc24f767d1b7a165266658d542af9e3f9bc11dd1a2d1f4695df009",
				r[0].Args[0],
			)

			file, err := ioutil.ReadFile(
				"testdata/tx_receipt_0xd919fe87c4bc24f767d1b7a165266658d542af9e3f9bc11dd1a2d1f4695df009.json",
			) // nolint
			assert.NoError(t, err)

			receipt := new(types.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()
	mockCurrencyFetcher.On(
		"FetchCurrency",
		ctx,
		uint64(1241186),
		mock.Anything,
	).Return(
		&RosettaTypes.Currency{
			Symbol:   TokenSymbol,
			Decimals: TokenDecimals,
			Metadata: map[string]interface{}{"token_address": opTokenContractAddress.String()}},
		nil,
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_1241186.json")
	assert.NoError(t, err)
	var correctResp *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(1241186),
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

func TestBlock_1502839_OPCriticalBug(t *testing.T) {
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

			file, err := ioutil.ReadFile("testdata/block_1502839.json")
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
				common.HexToHash("0x3ff079ba4ea0745401e9661d623550d24c9412ea9ad578bfbb0d441dadcce9bc").Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, tc, r[0].Args[1])

			file, err := ioutil.ReadFile(
				"testdata/tx_trace_1502839.json",
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
				"0x3ff079ba4ea0745401e9661d623550d24c9412ea9ad578bfbb0d441dadcce9bc",
				r[0].Args[0],
			)

			file, err := ioutil.ReadFile(
				"testdata/tx_receipt_0x3ff079ba4ea0745401e9661d623550d24c9412ea9ad578bfbb0d441dadcce9bc.json",
			)
			assert.NoError(t, err)

			receipt := new(types.Receipt)
			assert.NoError(t, receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := ioutil.ReadFile("testdata/block_response_1502839.json")
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
