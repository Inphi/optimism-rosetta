package optimism

import (
	"math/big"

	EthCommon "github.com/ethereum/go-ethereum/common"
	EthHexutil "github.com/ethereum/go-ethereum/common/hexutil"
	EthMath "github.com/ethereum/go-ethereum/common/math"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
)

// InnerBedrockTransaction is the JSON representation of a bedrock transaction.
type InnerBedrockTransaction interface {
	Hash() EthCommon.Hash
	To() *EthCommon.Address
	Gas() uint64
	GasPrice() *big.Int
	GetType() uint64
	GetValue() *big.Int
	EffectiveGasTip(*big.Int) (*big.Int, error)
}

// transaction is a JSON representation of a Transaction
type transaction struct {
	Type                 EthHexutil.Uint64  `json:"type"`
	Nonce                *EthHexutil.Uint64 `json:"nonce"`
	Price                *EthHexutil.Big    `json:"gasPrice"`
	MaxPriorityFeePerGas *EthHexutil.Big    `json:"maxPriorityFeePerGas"`
	MaxFeePerGas         *EthHexutil.Big    `json:"maxFeePerGas"`
	GasLimit             EthHexutil.Uint64  `json:"gas"`
	Value                *EthHexutil.Big    `json:"value"`
	Data                 *EthHexutil.Bytes  `json:"input"`
	V                    *EthHexutil.Big    `json:"v"`
	R                    *EthHexutil.Big    `json:"r"`
	S                    *EthHexutil.Big    `json:"s"`
	Recipient            *EthCommon.Address `json:"to"`
	ChainID              *EthHexutil.Big    `json:"chainId,omitempty"`
	HashValue            EthCommon.Hash     `json:"hash"`
}

// IsDepositTx returns true if the transaction is a deposit tx type.
func (t *transaction) IsDepositTx() bool {
	return t.Type == L1ToL2DepositType
}

// GetValue returns the value of the transaction.
//
//nolint:golint
func (t *transaction) GetValue() *big.Int {
	return t.Value.ToInt()
}

// Hash returns the hash of the transaction.
func (t *transaction) Hash() EthCommon.Hash {
	return t.HashValue
}

// To returns the recipient of the transaction.
//
//nolint:golint
func (t *transaction) To() *EthCommon.Address {
	if t.Recipient == nil {
		return nil
	}
	return t.Recipient
}

// Gas returns the gas limit of the transaction.
func (t *transaction) Gas() uint64 {
	return uint64(t.GasLimit)
}

// GetType returns the type of the transaction.
func (t *transaction) GetType() uint64 {
	return uint64(t.Type)
}

// GasPrice returns the gas price of the transaction.
func (t *transaction) GasPrice() *big.Int {
	if t.Price == nil {
		return big.NewInt(0)
	}
	return (*big.Int)(t.Price)
}

// GasTipCap returns the gas tip cap of the transaction.
func (t *transaction) GasTipCap() *big.Int { return t.MaxPriorityFeePerGas.ToInt() }

func (t *transaction) GasFeeCap() *big.Int { return t.MaxPriorityFeePerGas.ToInt() }

// EffectiveGasTip returns the effective miner gasTipCap for the given base fee.
// Note: if the effective gasTipCap is negative, this method returns both error
// the actual negative value, _and_ ErrGasFeeCapTooLow
func (t *transaction) EffectiveGasTip(baseFee *big.Int) (*big.Int, error) {
	if t.Type == L1ToL2DepositType {
		return new(big.Int), nil
	}
	if baseFee == nil {
		return t.GasTipCap(), nil
	}
	var err error
	gasFeeCap := t.GasFeeCap()
	if gasFeeCap.Cmp(baseFee) == -1 {
		err = EthTypes.ErrGasFeeCapTooLow
	}
	return EthMath.BigMin(t.GasTipCap(), gasFeeCap.Sub(gasFeeCap, baseFee)), err
}
