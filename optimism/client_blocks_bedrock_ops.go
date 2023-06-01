package optimism

import (
	"log"
	"math/big"
	"strings"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
)

const ProxyContractFilter = "0x420000000000000000000000000000000000"
const ImplementationContractFilter = "0xc0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d3"

// ParseOps mimics the down-stream implementation of [rosetta-geth-sdk], exposing a hook for down-stream clients.
func (ec *Client) ParseOps(
	tx *bedrockTransaction,
) ([]*RosettaTypes.Operation, error) {
	var ops []*RosettaTypes.Operation

	feeOps, err := FeeOps(tx)
	if err != nil {
		return nil, err
	}
	ops = append(ops, feeOps...)
	ops = append(ops, MintOps(tx, len(ops))...)
	tracedOps := TraceOps(tx.Trace, len(ops))
	ops = append(ops, tracedOps...)

	return ops, nil
}

// MintOps constructs a list of [RosettaTypes.Operation]s for an Optimism Deposit or "mint" transaction.
func MintOps(tx *bedrockTransaction, startIndex int) []*RosettaTypes.Operation {
	if !tx.IsDepositTx() {
		return nil
	}

	opIndex := int64(startIndex)
	// "CALL" is used here to remain backwards-compatible with pre-bedrock Rosetta behavior
	opType := CallOpType
	opStatus := SuccessStatus
	fromAddress := MustChecksum(tx.From.String())
	amount := Amount(tx.Transaction.GetValue(), Currency)

	return []*RosettaTypes.Operation{
		GenerateOp(opIndex, nil, opType, opStatus, fromAddress, amount, nil),
	}
}

// TraceOps constructs [RosettaTypes.Operation]s from a list of [FlatCall]s.
//
//nolint:gocognit
func TraceOps(calls []*FlatCall, startIndex int) []*RosettaTypes.Operation {
	var ops []*RosettaTypes.Operation
	if len(calls) == 0 {
		return ops
	}

	destroyedAccountBalance := make(map[string]*big.Int)
	for _, call := range calls {
		// Handle the case where not all operation statuses are successful
		metadata := map[string]interface{}{}
		opStatus := SuccessStatus
		if call.Revert {
			opStatus = FailureStatus
			metadata["error"] = call.ErrorMessage
		}

		opType := strings.ToUpper(call.Type)
		if opType == "" {
			opType = CallOpType
		}

		// Checksum addresses
		fromAddress := MustChecksum(call.From.String())
		toAddress := MustChecksum(call.To.String())

		// Parse value
		var zeroValue bool
		if call.Value.Sign() == 0 {
			zeroValue = true
		}

		// Skip all 0 value CallType operations
		shouldAdd := true
		if zeroValue && CallType(call.Type) {
			shouldAdd = false
		}

		if shouldAdd {
			// Generate "from" operation
			fromOpIndex := int64(len(ops) + startIndex)
			fromAmount := Amount(new(big.Int).Neg(call.Value), Currency)
			fromOp := GenerateOp(fromOpIndex, nil, opType, opStatus, fromAddress, fromAmount, metadata)
			if _, ok := destroyedAccountBalance[fromAddress]; ok && opStatus == SuccessStatus {
				destroyedAccountBalance[fromAddress] = new(big.Int).Sub(destroyedAccountBalance[fromAddress], call.Value)
			}
			ops = append(ops, fromOp)
		}

		// Add to the destroyed account balance if SELFDESTRUCT, and overwrite existing balance.
		if opType == SelfDestructOpType {
			destroyedAccountBalance[fromAddress] = new(big.Int)

			// If destination of SELFDESTRUCT is self, we should skip.
			// In the EVM, the balance is reset after the balance is increased on the destination, so this is a no-op.
			if fromAddress == toAddress {
				continue
			}
		}

		// Skip empty to addresses (this may not
		// actually occur but leaving it as a
		// sanity check)
		if len(call.To.String()) == 0 {
			continue
		}

		// If the account is resurrected, we remove it from the destroyed account balance map.
		if CreateType(opType) {
			delete(destroyedAccountBalance, toAddress)
		}

		// Generate "to" operation
		if shouldAdd {
			lastOpIndex := ops[len(ops)-1].OperationIdentifier.Index
			toOpIndex := lastOpIndex + 1
			toRelatedOps := []*RosettaTypes.OperationIdentifier{
				{
					Index: lastOpIndex,
				},
			}
			toAmount := Amount(new(big.Int).Abs(call.Value), Currency)
			toOp := GenerateOp(toOpIndex, toRelatedOps, opType, opStatus, toAddress, toAmount, metadata)
			if _, ok := destroyedAccountBalance[toAddress]; ok && opStatus == SuccessStatus {
				destroyedAccountBalance[toAddress] = new(big.Int).Add(destroyedAccountBalance[toAddress], call.Value)
			}
			ops = append(ops, toOp)
		}
	}

	// Zero-out all destroyed accounts that are removed during transaction finalization.
	for acct, balance := range destroyedAccountBalance {
		if _, ok := ChecksumAddress(acct); !ok || balance.Sign() == 0 {
			continue
		}

		if balance.Sign() < 0 {
			log.Fatalf("negative balance for suicided account %s: %s\n", acct, balance.String())
		}

		// Generate "destruct" operation
		destructOpIndex := ops[len(ops)-1].OperationIdentifier.Index + 1
		destructOpType := DestructOpType
		destructOpStatus := RosettaTypes.String(SuccessStatus)
		address := acct
		amount := Amount(new(big.Int).Neg(balance), Currency)
		destructOp := GenerateOp(destructOpIndex, nil, destructOpType, *destructOpStatus, address, amount, nil)
		ops = append(ops, destructOp)
	}

	return ops
}

// FeeOps returns the fee operations for a given transaction.
func FeeOps(tx *bedrockTransaction) ([]*RosettaTypes.Operation, error) {
	if tx.IsDepositTx() {
		return nil, nil
	}

	var receipt EthTypes.Receipt
	if err := receipt.UnmarshalJSON(tx.Receipt.RawMessage); err != nil {
		return nil, err
	}

	sequencerFeeAmount := new(big.Int).Set(tx.FeeAmount)
	L1Fee := ExtractL1Fee(tx.Receipt)
	if L1Fee != nil {
		sequencerFeeAmount.Sub(sequencerFeeAmount, L1Fee)
	}
	if sequencerFeeAmount == nil {
		return nil, nil
	}

	feeRewarder := tx.Miner

	opType := FeeOpType
	opStatus := SuccessStatus
	fromAddress := MustChecksum(tx.From.String())
	txFeeLessFees := new(big.Int).Neg(tx.Receipt.TransactionFee)
	if tx.FeeBurned != nil {
		txFeeLessFees.Sub(txFeeLessFees, tx.FeeBurned)
	}
	fromAmount := Amount(txFeeLessFees, Currency)
	sequencerRelatedOps := []*RosettaTypes.OperationIdentifier{
		{
			Index: 0,
		},
	}
	sequencerAddress := MustChecksum(feeRewarder)
	sequencerAmount := Amount(sequencerFeeAmount, Currency)
	baseFeeVaultRelatedOps := []*RosettaTypes.OperationIdentifier{
		{
			Index: 0,
		},
	}
	baseFeeVaultAddress := BaseFeeVault.Hex()
	baseFeeVaultAmount := Amount(tx.FeeBurned, Currency)
	L1FeeVaultRelatedOps := []*RosettaTypes.OperationIdentifier{
		{
			Index: 0,
		},
	}
	L1FeeVaultAddress := L1FeeVault.Hex()
	L1FeeVaultAmount := Amount(L1Fee, Currency)

	ops := []*RosettaTypes.Operation{
		GenerateOp(0, nil, opType, opStatus, fromAddress, fromAmount, nil),
		GenerateOp(1, sequencerRelatedOps, opType, opStatus, sequencerAddress, sequencerAmount, nil),
		GenerateOp(2, baseFeeVaultRelatedOps, opType, opStatus, baseFeeVaultAddress, baseFeeVaultAmount, nil),
		GenerateOp(3, L1FeeVaultRelatedOps, opType, opStatus, L1FeeVaultAddress, L1FeeVaultAmount, nil),
	}

	return ops, nil
}

func GenerateOp(opIndex int64, relatedOps []*RosettaTypes.OperationIdentifier, opType string, opStatus string, address string, amount *RosettaTypes.Amount, metadata map[string]interface{}) *RosettaTypes.Operation {
	return &RosettaTypes.Operation{
		OperationIdentifier: &RosettaTypes.OperationIdentifier{
			Index: opIndex,
		},
		RelatedOperations: relatedOps,
		Type:              opType,
		Status:            RosettaTypes.String(opStatus),
		Account: &RosettaTypes.AccountIdentifier{
			Address: address,
		},
		Amount:   amount,
		Metadata: metadata,
	}
}
