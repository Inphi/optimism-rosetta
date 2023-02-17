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

// NewTransactionFromFields creates a new [transaction] from the fields
func NewTransactionFromFields(ty uint64, nonce uint64, price *big.Int, maxPriorityFee *big.Int, maxFee *big.Int, gasLim uint64, value *big.Int, data []byte, v *big.Int, r *big.Int, s *big.Int, recipient EthCommon.Address, chain *big.Int, hash EthCommon.Hash) *transaction {
	return &transaction{
		Type:                 (EthHexutil.Uint64)(ty),
		Nonce:                (*EthHexutil.Uint64)(&nonce),
		Price:                (*EthHexutil.Big)(price),
		MaxPriorityFeePerGas: (*EthHexutil.Big)(maxPriorityFee),
		MaxFeePerGas:         (*EthHexutil.Big)(maxFee),
		GasLimit:             (EthHexutil.Uint64)(gasLim),
		Value:                (*EthHexutil.Big)(value),
		Data:                 (*EthHexutil.Bytes)(&data),
		V:                    (*EthHexutil.Big)(v),
		R:                    (*EthHexutil.Big)(r),
		S:                    (*EthHexutil.Big)(s),
		Recipient:            (*EthCommon.Address)(&recipient),
		ChainID:              (*EthHexutil.Big)(chain),
		HashValue:            (EthCommon.Hash)(hash),
	}
}

// NewBedrockTransaction creates an unsigned legacy transaction.
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

func (t *transaction) GetValue() *big.Int {
	return t.Value.ToInt()
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
	if t.Price == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set((*big.Int)(t.Price))
}

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
		// return big.NewInt(0), nil
	}
	return EthMath.BigMin(t.GasTipCap(), gasFeeCap.Sub(gasFeeCap, baseFee)), err
}
