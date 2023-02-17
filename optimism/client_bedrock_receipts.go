package optimism

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
)

var eip1559TxType = 2
var ErrClientBlockOrphaned = errors.New("block orphaned")

// EffectiveGasPrice returns the price of gas charged to this Transaction to be included in the
// block.
func EffectiveGasPrice(tx InnerBedrockTransaction, baseFee *big.Int) (*big.Int, error) {
	if tx.GetType() != uint64(eip1559TxType) {
		gasPrice := tx.GasPrice()
		if gasPrice == nil {
			gasPrice = big.NewInt(0)
		}
		return gasPrice, nil
	}
	// For EIP-1559 the gas price is determined by the base fee & miner tip sinstead
	// of the tx-specified gas price.
	tip, err := tx.EffectiveGasTip(baseFee)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(tip, baseFee), nil
}

// ExtractStatus unmarshals a receipt status from a json marshalled raw message
func ExtractStatus(rosettaTxReceipt *RosettaTxReceipt) (uint64, error) {
	var receipt EthTypes.Receipt
	if err := json.Unmarshal(rosettaTxReceipt.RawMessage, &receipt); err != nil {
		return 0, err
	}
	return receipt.Status, nil
}

// getBedrockBlockReceipts returns the receipts for all transactions in a block.
func (ec *Client) getBedrockBlockReceipts(
	ctx context.Context,
	blockHash EthCommon.Hash,
	txs []BedrockRPCTransaction,
	baseFee *big.Int,
) ([]*RosettaTxReceipt, error) {
	receipts := make([]*RosettaTxReceipt, len(txs))
	if len(txs) == 0 {
		return receipts, nil
	}

	ethReceipts := make([]*EthTypes.Receipt, len(txs))
	reqs := make([]rpc.BatchElem, len(txs))
	for i := range reqs {
		reqs[i] = rpc.BatchElem{
			Method: "eth_getTransactionReceipt",
			Args:   []interface{}{txs[i].TxExtraInfo.TxHash.String()},
			Result: &ethReceipts[i],
		}
	}

	maxBatchSize := 25
	for i := 0; i < len(txs); i += maxBatchSize {
		if i+maxBatchSize < len(txs) {
			if err := ec.c.BatchCallContext(ctx, reqs[i:i+maxBatchSize]); err != nil {
				return nil, err
			}
		} else {
			if err := ec.c.BatchCallContext(ctx, reqs[i:]); err != nil {
				return nil, err
			}
		}
	}

	for i := range reqs {
		if reqs[i].Error != nil {
			return nil, reqs[i].Error
		}

		gasPrice, err := EffectiveGasPrice(txs[i].Tx, baseFee)
		if err != nil {
			return nil, err
		}
		gasUsed := new(big.Int).SetUint64(ethReceipts[i].GasUsed)
		feeAmount := new(big.Int).Mul(gasUsed, gasPrice)

		receiptJSON, err := ethReceipts[i].MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("unable to marshal receipt for %x: %v", txs[i].Tx.Hash().Hex(), err)
		}
		receipt := &RosettaTxReceipt{
			Type:           ethReceipts[i].Type,
			GasPrice:       gasPrice,
			GasUsed:        gasUsed,
			Logs:           ethReceipts[i].Logs,
			RawMessage:     receiptJSON,
			TransactionFee: feeAmount,
		}

		receipts[i] = receipt

		if ethReceipts[i] == nil {
			return nil, fmt.Errorf("got empty receipt for %x", txs[i].Tx.Hash().Hex())
		}

		if ethReceipts[i].BlockHash != blockHash {
			return nil, fmt.Errorf(
				"%w: expected block hash %s for Transaction but got %s",
				ErrClientBlockOrphaned,
				blockHash.Hex(),
				ethReceipts[i].BlockHash.Hex(),
			)
		}
	}

	return receipts, nil
}
