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
	"encoding/json"
	"math/big"

	OptimismCommon "github.com/ethereum-optimism/optimism/l2geth/common"
	OptimismTypes "github.com/ethereum-optimism/optimism/l2geth/core/types"
)

type txExtraInfo struct {
	BlockNumber *string                 `json:"blockNumber,omitempty"`
	BlockHash   *OptimismCommon.Hash    `json:"blockHash,omitempty"`
	From        *OptimismCommon.Address `json:"from,omitempty"`
}

type rpcTransaction struct {
	tx *OptimismTypes.Transaction
	txExtraInfo
}

// LoadedTransaction converts an [rpcTransaction] to a [legacyTransaction].
func (tx *rpcTransaction) LoadedTransaction() *legacyTransaction {
	ethTx := legacyTransaction{
		Transaction: tx.tx,
		From:        tx.txExtraInfo.From,
		BlockNumber: tx.txExtraInfo.BlockNumber,
		BlockHash:   tx.txExtraInfo.BlockHash,
	}
	return &ethTx
}

// UnmarshalJSON unmarshals an [rpcTransaction] from bytes.
func (tx *rpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

// legacyTransaction is a pre-bedrock transaction type.
type legacyTransaction struct {
	Transaction *OptimismTypes.Transaction
	From        *OptimismCommon.Address
	BlockNumber *string
	BlockHash   *OptimismCommon.Hash
	FeeAmount   *big.Int
	Miner       string
	Status      bool
	Trace       *Call
	RawTrace    json.RawMessage
	Receipt     *OptimismTypes.Receipt
}
