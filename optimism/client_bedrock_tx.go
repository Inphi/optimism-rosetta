package optimism

// import (
// 	"encoding/json"
// 	"errors"
// 	"fmt"
// 	"math/big"
// 	"sync/atomic"
// 	"time"

// 	EthCommon "github.com/ethereum/go-ethereum/common"
// 	EthHexutil "github.com/ethereum/go-ethereum/common/hexutil"
// 	EthTypes "github.com/ethereum/go-ethereum/core/types"
// )

// // InnerBedrockTransaction is the JSON representation of a bedrock transaction.
// type InnerBedrockTransaction struct {
// 	Type EthHexutil.Uint64 `json:"type"`

// 	// Common transaction fields:
// 	Nonce                *EthHexutil.Uint64 `json:"nonce"`
// 	GasPrice             *EthHexutil.Big    `json:"gasPrice"`
// 	MaxPriorityFeePerGas *EthHexutil.Big    `json:"maxPriorityFeePerGas"`
// 	MaxFeePerGas         *EthHexutil.Big    `json:"maxFeePerGas"`
// 	Gas                  *EthHexutil.Uint64 `json:"gas"`
// 	Value                *EthHexutil.Big    `json:"value"`
// 	Data                 *EthHexutil.Bytes  `json:"input"`
// 	V                    *EthHexutil.Big    `json:"v"`
// 	R                    *EthHexutil.Big    `json:"r"`
// 	S                    *EthHexutil.Big    `json:"s"`
// 	To                   *EthCommon.Address `json:"to"`

// 	// Deposit transaction fields
// 	SourceHash *EthCommon.Hash    `json:"sourceHash,omitempty"`
// 	From       *EthCommon.Address `json:"from,omitempty"`
// 	Mint       *EthHexutil.Big    `json:"mint,omitempty"`
// 	IsSystemTx *bool              `json:"isSystemTx,omitempty"`

// 	// Access list transaction fields:
// 	ChainID    *EthHexutil.Big      `json:"chainId,omitempty"`
// 	AccessList *EthTypes.AccessList `json:"accessList,omitempty"`

// 	// Only used for encoding:
// 	Hash EthCommon.Hash `json:"hash"`
// }

// // BedrockTransaction is a minimal bedrock transaction type that implements the required method set for the client.
// type BedrockTransaction struct {
// 	inner InnerBedrockTransaction // Consensus contents of a transaction
// 	time  time.Time               // Time first seen locally (spam avoidance)

// 	// caches
// 	hash atomic.Value
// 	size atomic.Value
// 	from atomic.Value

// 	// cache how much gas the tx takes on L1 for its share of rollup data
// 	rollupGas atomic.Value
// }

// // NewTx creates a new bedrock transaction type.
// func NewTx(inner InnerBedrockTransaction) *BedrockTransaction {
// 	tx := new(BedrockTransaction)
// 	tx.inner = inner
// 	return tx
// }

// // UnmarshalJSON unmarshals from JSON.
// func (tx *BedrockTransaction) UnmarshalJSON(input []byte) error {
// 	var dec InnerBedrockTransaction
// 	if err := json.Unmarshal(input, &dec); err != nil {
// 		return err
// 	}

// 	fmt.Printf("Unmarshalling JSON transaction...\n")

// 	// Validate fields according to transaction type.
// 	switch dec.Type {
// 	case EthTypes.LegacyTxType:
// 		if dec.Nonce == nil {
// 			return errors.New("missing required field 'nonce' in transaction")
// 		}
// 		if dec.GasPrice == nil {
// 			return errors.New("missing required field 'gasPrice' in transaction")
// 		}
// 		if dec.Gas == nil {
// 			return errors.New("missing required field 'gas' in transaction")
// 		}
// 		if dec.Value == nil {
// 			return errors.New("missing required field 'value' in transaction")
// 		}
// 		if dec.Data == nil {
// 			return errors.New("missing required field 'input' in transaction")
// 		}
// 		if dec.V == nil {
// 			return errors.New("missing required field 'v' in transaction")
// 		}
// 		itx.V = (*big.Int)(dec.V)
// 		if dec.R == nil {
// 			return errors.New("missing required field 'r' in transaction")
// 		}
// 		itx.R = (*big.Int)(dec.R)
// 		if dec.S == nil {
// 			return errors.New("missing required field 's' in transaction")
// 		}
// 		itx.S = (*big.Int)(dec.S)
// 		withSignature := itx.V.Sign() != 0 || itx.R.Sign() != 0 || itx.S.Sign() != 0
// 		if withSignature {
// 			if err := sanityCheckSignature(itx.V, itx.R, itx.S, true); err != nil {
// 				return err
// 			}
// 		}

// 	case EthTypes.AccessListTxType:
// 		var itx EthTypes.AccessListTx
// 		inner = &itx
// 		// Access list is optional for now.
// 		if dec.AccessList != nil {
// 			itx.AccessList = *dec.AccessList
// 		}
// 		if dec.ChainID == nil {
// 			return errors.New("missing required field 'chainId' in transaction")
// 		}
// 		itx.ChainID = (*big.Int)(dec.ChainID)
// 		if dec.To != nil {
// 			itx.To = dec.To
// 		}
// 		if dec.Nonce == nil {
// 			return errors.New("missing required field 'nonce' in transaction")
// 		}
// 		itx.Nonce = uint64(*dec.Nonce)
// 		if dec.GasPrice == nil {
// 			return errors.New("missing required field 'gasPrice' in transaction")
// 		}
// 		itx.GasPrice = (*big.Int)(dec.GasPrice)
// 		if dec.Gas == nil {
// 			return errors.New("missing required field 'gas' in transaction")
// 		}
// 		itx.Gas = uint64(*dec.Gas)
// 		if dec.Value == nil {
// 			return errors.New("missing required field 'value' in transaction")
// 		}
// 		itx.Value = (*big.Int)(dec.Value)
// 		if dec.Data == nil {
// 			return errors.New("missing required field 'input' in transaction")
// 		}
// 		itx.Data = *dec.Data
// 		if dec.V == nil {
// 			return errors.New("missing required field 'v' in transaction")
// 		}
// 		itx.V = (*big.Int)(dec.V)
// 		if dec.R == nil {
// 			return errors.New("missing required field 'r' in transaction")
// 		}
// 		itx.R = (*big.Int)(dec.R)
// 		if dec.S == nil {
// 			return errors.New("missing required field 's' in transaction")
// 		}
// 		itx.S = (*big.Int)(dec.S)
// 		withSignature := itx.V.Sign() != 0 || itx.R.Sign() != 0 || itx.S.Sign() != 0
// 		if withSignature {
// 			if err := sanityCheckSignature(itx.V, itx.R, itx.S, false); err != nil {
// 				return err
// 			}
// 		}

// 	case EthTypes.DynamicFeeTxType:
// 		var itx EthTypes.DynamicFeeTx
// 		inner = &itx
// 		// Access list is optional for now.
// 		if dec.AccessList != nil {
// 			itx.AccessList = *dec.AccessList
// 		}
// 		if dec.ChainID == nil {
// 			return errors.New("missing required field 'chainId' in transaction")
// 		}
// 		itx.ChainID = (*big.Int)(dec.ChainID)
// 		if dec.To != nil {
// 			itx.To = dec.To
// 		}
// 		if dec.Nonce == nil {
// 			return errors.New("missing required field 'nonce' in transaction")
// 		}
// 		itx.Nonce = uint64(*dec.Nonce)
// 		if dec.MaxPriorityFeePerGas == nil {
// 			return errors.New("missing required field 'maxPriorityFeePerGas' for txdata")
// 		}
// 		itx.GasTipCap = (*big.Int)(dec.MaxPriorityFeePerGas)
// 		if dec.MaxFeePerGas == nil {
// 			return errors.New("missing required field 'maxFeePerGas' for txdata")
// 		}
// 		itx.GasFeeCap = (*big.Int)(dec.MaxFeePerGas)
// 		if dec.Gas == nil {
// 			return errors.New("missing required field 'gas' for txdata")
// 		}
// 		itx.Gas = uint64(*dec.Gas)
// 		if dec.Value == nil {
// 			return errors.New("missing required field 'value' in transaction")
// 		}
// 		itx.Value = (*big.Int)(dec.Value)
// 		if dec.Data == nil {
// 			return errors.New("missing required field 'input' in transaction")
// 		}
// 		itx.Data = *dec.Data
// 		if dec.V == nil {
// 			return errors.New("missing required field 'v' in transaction")
// 		}
// 		itx.V = (*big.Int)(dec.V)
// 		if dec.R == nil {
// 			return errors.New("missing required field 'r' in transaction")
// 		}
// 		itx.R = (*big.Int)(dec.R)
// 		if dec.S == nil {
// 			return errors.New("missing required field 's' in transaction")
// 		}
// 		itx.S = (*big.Int)(dec.S)
// 		withSignature := itx.V.Sign() != 0 || itx.R.Sign() != 0 || itx.S.Sign() != 0
// 		if withSignature {
// 			if err := sanityCheckSignature(itx.V, itx.R, itx.S, false); err != nil {
// 				return err
// 			}
// 		}

// 	// Locally defined transaction type for post-bedrock deposits.
// 	case L1ToL2DepositType:
// 		fmt.Printf("Found L1ToL2DepositType...\n")
// 		if dec.AccessList != nil || dec.MaxFeePerGas != nil ||
// 			dec.MaxPriorityFeePerGas != nil || (dec.Nonce != nil && *dec.Nonce != 0) {
// 			return errors.New("unexpected field(s) in deposit transaction")
// 		}
// 		if dec.GasPrice != nil && dec.GasPrice.ToInt().Cmp(EthCommon.Big0) != 0 {
// 			return errors.New("deposit transaction GasPrice must be 0")
// 		}
// 		if (dec.V != nil && dec.V.ToInt().Cmp(EthCommon.Big0) != 0) ||
// 			(dec.R != nil && dec.R.ToInt().Cmp(EthCommon.Big0) != 0) ||
// 			(dec.S != nil && dec.S.ToInt().Cmp(EthCommon.Big0) != 0) {
// 			return errors.New("deposit transaction signature must be 0 or unset")
// 		}
// 		var itx DepositTx
// 		inner = &itx
// 		if dec.To != nil {
// 			itx.To = dec.To
// 		}
// 		if dec.Gas == nil {
// 			return errors.New("missing required field 'gas' for txdata")
// 		}
// 		itx.Gas = uint64(*dec.Gas)
// 		if dec.Value == nil {
// 			return errors.New("missing required field 'value' in transaction")
// 		}
// 		itx.Value = (*big.Int)(dec.Value)
// 		// mint may be omitted or nil if there is nothing to mint.
// 		itx.Mint = (*big.Int)(dec.Mint)
// 		if dec.Data == nil {
// 			return errors.New("missing required field 'input' in transaction")
// 		}
// 		itx.Data = *dec.Data
// 		if dec.From == nil {
// 			return errors.New("missing required field 'from' in transaction")
// 		}
// 		itx.From = *dec.From
// 		if dec.SourceHash == nil {
// 			return errors.New("missing required field 'sourceHash' in transaction")
// 		}
// 		itx.SourceHash = *dec.SourceHash
// 		// IsSystemTx may be omitted. Defaults to false.
// 		if dec.IsSystemTx != nil {
// 			itx.IsSystemTransaction = *dec.IsSystemTx
// 		}
// 	default:
// 		return EthTypes.ErrTxTypeNotSupported
// 	}

// 	fmt.Printf("Constructed DepositTx: %v\n", inner)

// 	tx.inner = inner

// 	return nil
// }
