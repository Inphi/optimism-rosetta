package optimism

import (
	"math/big"

	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
)

type Transaction interface {
	Hash() common.Hash
	To() *common.Address
	Gas() uint64
	GasPrice() *big.Int
}

// transaction is a JSON representation of a Transaction
type transaction struct {
	Type                 hexutil.Uint64  `json:"type"`
	Nonce                *hexutil.Uint64 `json:"nonce"`
	Price                *hexutil.Big    `json:"gasPrice"`
	MaxPriorityFeePerGas *hexutil.Big    `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         *hexutil.Big    `json:"maxFeePerGas"`
	GasLimit             hexutil.Uint64  `json:"gas"`
	Value                *hexutil.Big    `json:"value"`
	Data                 *hexutil.Bytes  `json:"input"`
	V                    *hexutil.Big    `json:"v"`
	R                    *hexutil.Big    `json:"r"`
	S                    *hexutil.Big    `json:"s"`
	Recipient            *common.Address `json:"to"`
	ChainID              *hexutil.Big    `json:"chainId,omitempty"`
	HashValue            common.Hash     `json:"hash"`
}

// implement Transaction interface
func (t *transaction) Hash() common.Hash {
	return t.HashValue
}

func (t *transaction) To() *common.Address {
	if t.Recipient == nil {
		return nil
	}
	to := *t.Recipient
	return &to
}

func (t *transaction) Gas() uint64 {
	return uint64(t.GasLimit)
}

func (t *transaction) GasPrice() *big.Int {
	return new(big.Int).Set((*big.Int)(t.Price))
}
