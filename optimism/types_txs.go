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

// LoadedTransaction converts an [rpcTransaction] to a [LoadedTransaction].
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

// LoadedTransaction is an interface for a parsed transaction type.
type LoadedTransaction interface {
	IsDepositTx() bool
	FromRPCTransaction(*rpcTransaction) LoadedTransaction
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

	Trace    *Call
	RawTrace json.RawMessage
	Receipt  *OptimismTypes.Receipt
}

// NewLegacyTransaction creates a new bedrock transaction.
//
//nolint:golint
func NewLegacyTransaction() *legacyTransaction {
	return &legacyTransaction{}
}

// IsDepositTx returns true if the transaction is a deposit tx type.
func (lt *legacyTransaction) IsDepositTx() bool {
	// TODO: how to determine if deposit tx for legacy transactions?
	return false
}

// FromRPCTransaction constructs a [legacyTransaction] from an [rpcTransaction].
func (lt *legacyTransaction) FromRPCTransaction(tx *rpcTransaction) *legacyTransaction {
	ethTx := &legacyTransaction{
		Transaction: tx.tx,
		From:        tx.txExtraInfo.From,
		BlockNumber: tx.txExtraInfo.BlockNumber,
		BlockHash:   tx.txExtraInfo.BlockHash,
	}
	return ethTx
}
