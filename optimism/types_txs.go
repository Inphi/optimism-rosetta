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
