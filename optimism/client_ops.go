package optimism

import (
	"math/big"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	OptimismTypes "github.com/ethereum-optimism/optimism/l2geth/core/types"
)

func feeOps(tx *legacyTransaction) []*RosettaTypes.Operation {
	return []*RosettaTypes.Operation{
		{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 0,
			},
			Type:   FeeOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: MustChecksum(tx.From.String()),
			},
			Amount: &RosettaTypes.Amount{
				Value:    new(big.Int).Neg(tx.FeeAmount).String(),
				Currency: Currency,
			},
		},
		{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 1,
			},
			RelatedOperations: []*RosettaTypes.OperationIdentifier{
				{
					Index: 0,
				},
			},
			Type:   FeeOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: MustChecksum(tx.Miner),
			},
			Amount: &RosettaTypes.Amount{
				Value:    tx.FeeAmount.String(),
				Currency: Currency,
			},
		},
	}
}

// Set the fees of applicable zero gas transactions to zero
func patchFeeOps(chainID *big.Int, block *OptimismTypes.Block, tx *OptimismTypes.Transaction, ops []*RosettaTypes.Operation) {
	if chainID.Cmp(goerliChainID) != 0 {
		return
	}
	if tx.GasPrice().Uint64() == 0 && block.NumberU64() < goerliRollupFeeEnforcementBlockHeight {
		for _, op := range ops {
			if op.Type == FeeOpType {
				op.Amount.Value = "0"
			}
		}
	}
}

// Amount returns a Rosetta Amount from a big.Int and currency.
func Amount(value *big.Int, currency *RosettaTypes.Currency) *RosettaTypes.Amount {
	if value == nil {
		return nil
	}
	return &RosettaTypes.Amount{
		Value:    value.String(),
		Currency: currency,
	}
}
