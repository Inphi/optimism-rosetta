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
	"errors"
	"fmt"
	"math/big"

	L2GethTypes "github.com/ethereum-optimism/optimism/l2geth/core/types"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
)

var eip1559TxType = 2
var ErrClientBlockOrphaned = errors.New("block orphaned")

// EffectiveGasPrice returns the price of gas charged to this Transaction to be included in the
// block.
func EffectiveGasPrice(tx InnerBedrockTransaction, baseFee *big.Int) (*big.Int, error) {
	if tx.GetType() != uint64(eip1559TxType) {
		gasPrice := tx.GasPrice()
		if gasPrice == nil {
			gasPrice = big.NewInt(0)
		}
		return gasPrice, nil
	}
	// For EIP-1559 the gas price is determined by the base fee & miner tip instead
	// of the tx-specified gas price.
	tip, err := tx.EffectiveGasTip(baseFee)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(tip, baseFee), nil
}

// ExtractStatus unmarshals a receipt status from a json marshalled raw message
func ExtractStatus(rosettaTxReceipt *RosettaTxReceipt) (uint64, error) {
	var receipt EthTypes.Receipt
	if err := json.Unmarshal(rosettaTxReceipt.RawMessage, &receipt); err != nil {
		return 0, err
	}
	return receipt.Status, nil
}

// ExtractL1Fee attempts to unmarshal an [L1Fee] from the RawMessage field in a [RosettaTxReceipt]
// TODO: hoist this up to initial receipt unmarshalling in the bedrock block handler so we can error early
func ExtractL1Fee(rosettaTxReceipt *RosettaTxReceipt) *big.Int {
	var receipt L2GethTypes.Receipt
	if err := json.Unmarshal(rosettaTxReceipt.RawMessage, &receipt); err != nil {
		return nil
	}
	return receipt.L1Fee
}

// getBedrockBlockReceipts returns the receipts for all transactions in a block.
func (ec *Client) getBedrockBlockReceipts(
	ctx context.Context,
	blockHash EthCommon.Hash,
	txs []BedrockRPCTransaction,
	baseFee *big.Int,
) ([]*RosettaTxReceipt, error) {
	receipts := make([]*RosettaTxReceipt, len(txs))
	if len(txs) == 0 {
		return receipts, nil
	}

	ethReceipts := make([]*EthTypes.Receipt, len(txs))
	rawReceipts := make([]json.RawMessage, len(txs))
	reqs := make([]rpc.BatchElem, len(txs))
	for i := range reqs {
		reqs[i] = rpc.BatchElem{
			Method: "eth_getTransactionReceipt",
			Args:   []interface{}{txs[i].TxExtraInfo.TxHash.String()},
			Result: &rawReceipts[i],
		}
	}

	maxBatchSize := 25
	for i := 0; i < len(txs); i += maxBatchSize {
		if i+maxBatchSize < len(txs) {
			if err := ec.c.BatchCallContext(ctx, reqs[i:i+maxBatchSize]); err != nil {
				return nil, err
			}
		} else {
			if err := ec.c.BatchCallContext(ctx, reqs[i:]); err != nil {
				return nil, err
			}
		}
	}

	for i := range reqs {
		if reqs[i].Error != nil {
			return nil, reqs[i].Error
		}

		// Unmarshal the raw receipt into a typed receipt
		if err := json.Unmarshal(rawReceipts[i], &ethReceipts[i]); err != nil {
			return nil, fmt.Errorf("unable to unmarshal receipt for %x: %v", txs[i].Tx.Hash().Hex(), err)
		}

		gasPrice, err := EffectiveGasPrice(txs[i].Tx, baseFee)
		if err != nil {
			return nil, err
		}
		gasUsed := new(big.Int).SetUint64(ethReceipts[i].GasUsed)
		feeAmount := new(big.Int).Mul(gasUsed, gasPrice)
		var r L2GethTypes.Receipt
		if err := json.Unmarshal(rawReceipts[i], &r); err == nil {
			feeAmount.Add(feeAmount, r.L1Fee)
		}

		receipt := &RosettaTxReceipt{
			Type:           ethReceipts[i].Type,
			GasPrice:       gasPrice,
			GasUsed:        gasUsed,
			Logs:           ethReceipts[i].Logs,
			RawMessage:     rawReceipts[i],
			TransactionFee: feeAmount,
		}

		receipts[i] = receipt

		if ethReceipts[i] == nil {
			return nil, fmt.Errorf("got empty receipt for %x", txs[i].Tx.Hash().Hex())
		}

		if ethReceipts[i].BlockHash != blockHash {
			return nil, fmt.Errorf(
				"%w: expected block hash %s for Transaction but got %s",
				ErrClientBlockOrphaned,
				blockHash.Hex(),
				ethReceipts[i].BlockHash.Hex(),
			)
		}
	}

	return receipts, nil
}
