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

package services

import (
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// *JSONMap functions are needed because `types.MarshalMap/types.UnmarshalMap`
// does not respect custom JSON marshalers.

// marshalJSONMap converts an interface into a map[string]interface{}.
func marshalJSONMap(i interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}

	return m, nil
}

// unmarshalJSONMap converts map[string]interface{} into a interface{}.
func unmarshalJSONMap(m map[string]interface{}, i interface{}) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, i)
}

func AsEthTransaction(tx *transaction) *types.Transaction {
	var to *common.Address
	if tx.To != "" {
		x := common.HexToAddress(tx.To)
		to = &x
	}
	if eip1559Tx := tx.GasTipCap != nil && tx.GasFeeCap != nil; eip1559Tx {
		return types.NewTx(&types.DynamicFeeTx{
			Nonce:     tx.Nonce,
			GasTipCap: tx.GasTipCap,
			GasFeeCap: tx.GasFeeCap,
			Gas:       tx.GasLimit,
			To:        to,
			Value:     tx.Value,
			Data:      tx.Data,
		})
	} else {
		return types.NewTx(&types.LegacyTx{
			Nonce:    tx.Nonce,
			GasPrice: tx.GasPrice,
			Gas:      tx.GasLimit,
			To:       to,
			Value:    tx.Value,
			Data:     tx.Data,
		})
	}
}
