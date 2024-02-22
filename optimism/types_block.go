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
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
)

// rpcHeader represents the header returned via JSON-RPC.
// It may not contain all header fields returned via JSON-RPC, but the Hash field is always correct.
type rpcHeader struct {
	EthTypes.Header
	Hash common.Hash // the hash provided via JSON-RPC
}

func (h *rpcHeader) UnmarshalJSON(input []byte) error {
	type Header struct {
		ParentHash  *common.Hash         `json:"parentHash"`
		UncleHash   *common.Hash         `json:"sha3Uncles"`
		Coinbase    *common.Address      `json:"miner"`
		Root        *common.Hash         `json:"stateRoot"`
		TxHash      *common.Hash         `json:"transactionsRoot"`
		ReceiptHash *common.Hash         `json:"receiptsRoot"`
		Bloom       *EthTypes.Bloom      `json:"logsBloom"`
		Difficulty  *hexutil.Big         `json:"difficulty"`
		Number      *hexutil.Big         `json:"number"`
		GasLimit    *hexutil.Uint64      `json:"gasLimit"`
		GasUsed     *hexutil.Uint64      `json:"gasUsed"`
		Time        *hexutil.Uint64      `json:"timestamp"`
		Extra       *hexutil.Bytes       `json:"extraData"`
		MixDigest   *common.Hash         `json:"mixHash"`
		Nonce       *EthTypes.BlockNonce `json:"nonce"`
		BaseFee     *hexutil.Big         `json:"baseFeePerGas"`
		Hash        *common.Hash         `json:"hash"`
	}
	var dec Header
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.ParentHash == nil {
		return errors.New("missing required field 'parentHash' for Header")
	}
	h.ParentHash = *dec.ParentHash
	if dec.UncleHash == nil {
		return errors.New("missing required field 'sha3Uncles' for Header")
	}
	h.UncleHash = *dec.UncleHash
	if dec.Coinbase != nil {
		h.Coinbase = *dec.Coinbase
	}
	if dec.Root == nil {
		return errors.New("missing required field 'stateRoot' for Header")
	}
	h.Root = *dec.Root
	if dec.TxHash == nil {
		return errors.New("missing required field 'transactionsRoot' for Header")
	}
	h.TxHash = *dec.TxHash
	if dec.ReceiptHash == nil {
		return errors.New("missing required field 'receiptsRoot' for Header")
	}
	h.ReceiptHash = *dec.ReceiptHash
	if dec.Bloom == nil {
		return errors.New("missing required field 'logsBloom' for Header")
	}
	h.Bloom = *dec.Bloom
	if dec.Difficulty == nil {
		return errors.New("missing required field 'difficulty' for Header")
	}
	h.Difficulty = (*big.Int)(dec.Difficulty)
	if dec.Number == nil {
		return errors.New("missing required field 'number' for Header")
	}
	h.Number = (*big.Int)(dec.Number)
	if dec.GasLimit == nil {
		return errors.New("missing required field 'gasLimit' for Header")
	}
	h.GasLimit = uint64(*dec.GasLimit)
	if dec.GasUsed == nil {
		return errors.New("missing required field 'gasUsed' for Header")
	}
	h.GasUsed = uint64(*dec.GasUsed)
	if dec.Time == nil {
		return errors.New("missing required field 'timestamp' for Header")
	}
	h.Time = uint64(*dec.Time)
	if dec.Extra == nil {
		return errors.New("missing required field 'extraData' for Header")
	}
	h.Extra = *dec.Extra
	if dec.MixDigest != nil {
		h.MixDigest = *dec.MixDigest
	}
	if dec.Nonce != nil {
		h.Nonce = *dec.Nonce
	}
	if dec.BaseFee != nil {
		h.BaseFee = (*big.Int)(dec.BaseFee)
	}
	if dec.Hash == nil {
		return errors.New("missing required field 'hash' for Header")
	}
	h.Hash = *dec.Hash
	return nil
}
