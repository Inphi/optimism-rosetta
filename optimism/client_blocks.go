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
	"math/big"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
)

// toBlockNumArg returns a jsonrpc string identifier for a block.
// If the provided integer is nil, the latest block is returned.
func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	return hexutil.EncodeBig(number)
}

// blockByNumber retrieves a block by a given number from the internal client.
// If index is nil, the latest block is retrieved.
func (ec *Client) blockByNumber(
	ctx context.Context,
	index *int64,
	showTxDetails bool,
) (map[string]interface{}, error) {
	var blockIndex string
	if index == nil {
		blockIndex = toBlockNumArg(nil)
	} else {
		blockIndex = toBlockNumArg(big.NewInt(*index))
	}

	r := make(map[string]interface{})
	err := ec.c.CallContext(ctx, &r, "eth_getBlockByNumber", blockIndex, showTxDetails)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}

	return r, err
}

// Block returns a populated block at the *RosettaTypes.PartialBlockIdentifier.
// If neither the hash or index is populated in the *RosettaTypes.PartialBlockIdentifier,
// the current (aka latest) block is returned.
func (ec *Client) Block(
	ctx context.Context,
	blockIdentifier *RosettaTypes.PartialBlockIdentifier,
) (*RosettaTypes.Block, error) {
	// Derive block method and id
	derivedBlockMethod := "eth_getBlockByNumber"
	derivedBlockID := toBlockNumArg(nil)
	if blockIdentifier != nil {
		if blockIdentifier.Hash != nil {
			derivedBlockMethod = "eth_getBlockByHash"
			derivedBlockID = *blockIdentifier.Hash
		}

		if blockIdentifier.Index != nil {
			derivedBlockMethod = "eth_getBlockByNumber"
			derivedBlockID = toBlockNumArg(big.NewInt(*blockIdentifier.Index))
		}
	}

	return ec.disptachBlockRequest(ctx, derivedBlockMethod, derivedBlockID, true)
}

// dispatchBlockRequest dispatches a block request to the correct block fetcher.
func (ec *Client) disptachBlockRequest(
	ctx context.Context,
	blockMethod string,
	args ...interface{},
) (*RosettaTypes.Block, error) {
	// Attempt pre-bedrock block + header fetch
	header, block, raw, err := ec.getBlock(ctx, blockMethod, args...)
	if err == nil {
		preBedrock := ec.IsPreBedrock(header.Number)
		if preBedrock {
			return ec.getParsedBlock(ctx, header, block)
		}
	}
	// Block fetch errors should short-circuit
	if err != nil && err.IsBlockFetchError() {
		return nil, err.Err
	}

	// Revert to bedrock otherwise
	return ec.getParsedBedrockBlock(ctx, raw)
}
