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
	"fmt"

	"github.com/ethereum-optimism/optimism/l2geth/common"
	L2Eth "github.com/ethereum-optimism/optimism/l2geth/eth"
	EthCommon "github.com/ethereum/go-ethereum/common"
)

// geth traces types
type rpcCall struct {
	Result *Call `json:"result"`
}

// TraceTransactions returns traces for each of the given transactions.
// TraceTransactions uses `debug_traceTransaction` under the hood.
func (ec *Client) TraceTransactions(
	ctx context.Context,
	blockHash EthCommon.Hash,
	txs []BedrockRPCTransaction,
) (map[string][]*FlatCall, error) {
	if err := ec.traceSemaphore.Acquire(ctx, semaphoreTraceWeight); err != nil {
		return nil, err
	}
	defer ec.traceSemaphore.Release(semaphoreTraceWeight)

	m := make(map[string][]*FlatCall)
	traces := make([]*Call, len(txs))
	if len(txs) == 0 {
		return m, nil
	}

	// Check the trace cache
	if ec.traceCache != nil {
		for i := range txs {
			result, err := ec.traceCache.FetchTransaction(ctx, common.Hash(*txs[i].TxHash))
			if err != nil {
				return nil, err
			}
			traces[i] = result
			flatCalls := FlattenTraces(traces[i], []*FlatCall{})
			txHash := common.Hash(*txs[i].TxHash).Hex()
			if txHash == "" {
				return nil, fmt.Errorf("could not get %dth tx hash for block %s", i, blockHash.Hex())
			}
			m[txHash] = flatCalls
		}
		return m, nil
	}

	// Fetch traces sequentially to avoid DoS'ing the backend
	for i := range txs {
		txHash := common.Hash(*txs[i].TxHash).Hex()
		if err := ec.c.CallContext(ctx, &traces[i], "debug_traceTransaction", txHash, ec.getBedrockTraceConfig()); err != nil {
			return nil, err
		}
		if traces[i] == nil {
			return nil, fmt.Errorf("got empty trace for %x", txHash)
		}
		flatCalls := FlattenTraces(traces[i], []*FlatCall{})
		// Ethereum native traces are guaranteed to return all transactions
		if txHash == "" {
			return nil, fmt.Errorf("could not get %dth tx hash for block %s", i, blockHash.Hex())
		}
		m[txHash] = flatCalls
	}

	return m, nil
}

// TraceBlockByHash returns the Transaction traces of all transactions in the block
func (ec *Client) TraceBlockByHash(
	ctx context.Context,
	blockHash EthCommon.Hash,
	txs []BedrockRPCTransaction,
) (map[string][]*FlatCall, error) {
	if err := ec.traceSemaphore.Acquire(ctx, semaphoreTraceWeight); err != nil {
		return nil, err
	}
	defer ec.traceSemaphore.Release(semaphoreTraceWeight)

	var calls []*rpcCall
	var raw json.RawMessage

	tracingConfig := ec.getBedrockTraceConfig()
	err := ec.c.CallContext(ctx, &raw, "debug_traceBlockByHash", blockHash, tracingConfig)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil, err
	}
	m := make(map[string][]*FlatCall)
	for i, tx := range calls {
		if tx.Result.Type == "" {
			// ignore calls with an empty type
			continue
		}
		flatCalls := FlattenTraces(tx.Result, []*FlatCall{})
		// Ethereum native traces are guaranteed to return all transactions
		txHash := txs[i].TxExtraInfo.TxHash.Hex()
		if txHash == "" {
			return nil, fmt.Errorf("could not get %dth tx hash for block %s", i, blockHash.Hex())
		}
		m[txHash] = flatCalls
	}
	return m, nil
}

func (ec *Client) getBedrockTraceConfig() *L2Eth.TraceConfig {
	// NOTE: By default, we replace the TraceConfig here since l2geth and op-geth have different tracings
	tracingConfig := ec.tc
	if !ec.customBedrockTracer {
		tracer := "callTracer"
		tracingConfig = &L2Eth.TraceConfig{
			LogConfig: ec.tc.LogConfig,
			Tracer:    &tracer,
			Timeout:   ec.tc.Timeout,
			Reexec:    ec.tc.Reexec,
		}
	}
	return tracingConfig
}

// FlattenTraces recursively flattens all traces.
func FlattenTraces(data *Call, flattened []*FlatCall) []*FlatCall {
	if data == nil {
		return flattened
	}
	results := append(flattened, data.flatten()) //nolint
	for _, child := range data.Calls {
		// Ensure all children of a reverted call
		// are also reverted!
		if data.Revert {
			child.Revert = true

			// Copy error message from parent
			// if child does not have one
			if len(child.ErrorMessage) == 0 {
				child.ErrorMessage = data.ErrorMessage
			}
		}

		children := FlattenTraces(child, flattened)
		results = append(results, children...)
	}
	return results
}
