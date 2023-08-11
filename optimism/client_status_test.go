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
	"os"
	"testing"

	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	"github.com/ethereum-optimism/optimism/l2geth/core/types"
	"github.com/ethereum/go-ethereum/common/hexutil"
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
		"safe",
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
		c:               mockJSONRPC,
		g:               mockGraphQL,
		traceSemaphore:  semaphore.NewWeighted(100),
		supportsSyncing: true,
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"safe",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			header := args.Get(1).(**types.Header)
			file, err := os.ReadFile("testdata/basic_header.json")
			assert.NoError(t, err)

			*header = new(types.Header)

			assert.NoError(t, (*header).UnmarshalJSON(file))
		},
	).Once()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_syncing",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			rpcp := args.Get(1).(*json.RawMessage)
			j, err := json.Marshal(&rpcProgress{
				CurrentBlock: hexutil.Uint64(8916656),
				HighestBlock: hexutil.Uint64(8916656),
			})
			assert.NoError(t, err)
			rawMessage := json.RawMessage(j)
			*rpcp = rawMessage
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
	assert.Equal(t, peers, []*RosettaTypes.Peer{})
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
		supportsSyncing: true,
	}

	ctx := context.Background()
	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"safe",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			header := args.Get(1).(**types.Header)
			file, err := os.ReadFile("testdata/basic_header.json")
			assert.NoError(t, err)

			*header = new(types.Header)

			assert.NoError(t, (*header).UnmarshalJSON(file))
		},
	).Once()

	mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_syncing",
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			rpcp := args.Get(1).(*json.RawMessage)
			j, err := json.Marshal(&rpcProgress{
				CurrentBlock: hexutil.Uint64(8916656),
				HighestBlock: hexutil.Uint64(8916656),
			})
			assert.NoError(t, err)
			rawMessage := json.RawMessage(j)
			*rpcp = rawMessage
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
	assert.Equal(t, peers, []*RosettaTypes.Peer{})
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)
}
