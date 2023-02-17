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

// NewTransaction creates an unsigned legacy transaction.
func NewBedrockTransaction(
	nonce uint64,
	to EthCommon.Address,
	amount *big.Int,
	gasLimit uint64,
	gasPrice *big.Int,
	data []byte,
) InnerBedrockTransaction {
	return &transaction{
		Nonce:     (*EthHexutil.Uint64)(&nonce),
		Recipient: &to,
		Value:     (*EthHexutil.Big)(amount),
		GasLimit:  (EthHexutil.Uint64)(gasLimit),
		Price:     (*EthHexutil.Big)(gasPrice),
		Data:      (*EthHexutil.Bytes)(&data),
	}
}

// IsDepositTx returns true if the transaction is a deposit tx type.
func (lt *transaction) IsDepositTx() bool {
	// TODO: how to determine if deposit tx for legacy transactions?
	return false
}

// FromRPCTransaction constructs a [legacyTransaction] from an [rpcTransaction].
func (lt *transaction) FromRPCTransaction(tx *rpcTransaction) *legacyTransaction {
	ethTx := &legacyTransaction{
		Transaction: tx.tx,
		From:        tx.txExtraInfo.From,
		BlockNumber: tx.txExtraInfo.BlockNumber,
		BlockHash:   tx.txExtraInfo.BlockHash,
	}
	return ethTx
}

func (t *transaction) Hash() EthCommon.Hash {
	return t.HashValue
}

func (t *transaction) To() *EthCommon.Address {
	if t.Recipient == nil {
		return nil
	}
	to := *t.Recipient
	return &to
}

func (t *transaction) Gas() uint64 {
	return uint64(t.GasLimit)
}

func (t *transaction) GetType() uint64 {
	return uint64(t.Type)
}

func (t *transaction) GasPrice() *big.Int {
	return new(big.Int).Set((*big.Int)(t.Price))
}

func (t *transaction) GasTipCap() *big.Int { return new(big.Int) }

func (t *transaction) GasFeeCap() *big.Int { return new(big.Int) }

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
