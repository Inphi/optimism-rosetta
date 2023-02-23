package optimism

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	"github.com/ethereum-optimism/optimism/l2geth/core/types"
)

type rpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []rpcTransaction `json:"transactions"`
	UncleHashes  []common.Hash    `json:"uncles"`
}

var ErrBlockNotFound = fmt.Errorf("block not found")
var ErrBlockFetch = fmt.Errorf("failed to fetch block")
var ErrHeaderUnmarshal = fmt.Errorf("failed to unmarshal header")
var ErrBlockUnmarshal = fmt.Errorf("failed to unmarshal block")

type BlockError struct {
	Ty  error
	Err error
}

func (e *BlockError) IsBlockFetchError() bool {
	return e.Ty == ErrBlockFetch
}

func NewBlockError(ty error, err error) *BlockError {
	return &BlockError{Ty: ty, Err: err}
}

// getBlock returns a [types.Header] and [rpcBlock] for a given block or a respective error.
func (ec *Client) getBlock(
	ctx context.Context,
	blockMethod string,
	args ...interface{},
) (
	*types.Header,
	*rpcBlock,
	*json.RawMessage,
	*BlockError,
) {
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, blockMethod, args...)
	if err != nil {
		return nil, nil, &raw, NewBlockError(ErrBlockFetch, err)
	} else if len(raw) == 0 {
		return nil, nil, &raw, NewBlockError(ErrBlockNotFound, ethereum.NotFound)
	}

	// Decode header and transactions
	var head types.Header
	var body rpcBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, nil, &raw, NewBlockError(ErrHeaderUnmarshal, err)
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, nil, &raw, NewBlockError(ErrBlockUnmarshal, err)
	}
	return &head, &body, &raw, nil
}

func (ec *Client) getParsedBlock(
	ctx context.Context,
	head *types.Header,
	body *rpcBlock,
) (
	*RosettaTypes.Block,
	error,
) {
	// Get all transaction receipts
	receipts, err := ec.getBlockReceipts(ctx, body.Hash, body.Transactions)
	if err != nil {
		return nil, fmt.Errorf("%w: could not get receipts for %x", err, body.Hash[:])
	}

	// Get block traces (not possible to make idempotent block transaction trace requests)
	//
	// We fetch traces last because we want to avoid limiting the number of other
	// block-related data fetches we perform concurrently (we limit the number of
	// concurrent traces that are computed to 16 to avoid overwhelming geth).
	var traces []*Call
	var addTraces bool
	if head.Number.Int64() != GenesisBlockIndex { // not possible to get traces at genesis
		addTraces = true
		traces, err = ec.getTransactionTraces(ctx, body.Transactions)
		if err != nil {
			return nil, fmt.Errorf("%w: could not get traces for all txs in block %x", err, body.Hash[:])
		}
	}

	// Convert all txs to loaded txs
	txs := make([]*types.Transaction, len(body.Transactions))
	loadedTxs := make([]*legacyTransaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		txs[i] = tx.tx
		receipt := receipts[i]

		var feeAmount *big.Int
		if feeAmountInDupTx := originalFeeAmountInDupTx[body.Hash.Hex()]; feeAmountInDupTx == "" {
			gasUsedBig := new(big.Int).SetUint64(receipt.GasUsed)
			l2feeAmount := gasUsedBig.Mul(gasUsedBig, txs[i].GasPrice())
			feeAmount = l2feeAmount.Add(l2feeAmount, receipts[i].L1Fee)
		} else {
			// The fees reported in the tx receipt refers to the succeeding duplicate tx rather thaan the original.
			// We fix the feeAmount here to use the original so that balances are accounted for
			// Note that these duplicate transactions all failed to complete, so there aren't any additional mint/burn operations to account for.
			feeAmount = hexutil.MustDecodeBig(feeAmountInDupTx)
		}

		loadedTxs[i] = tx.LoadedTransaction()
		loadedTxs[i].Transaction = txs[i]
		loadedTxs[i].FeeAmount = feeAmount
		// Miner is fixed on Optimism and block rewards are sent internally to the OVM_SEQUENCER_FEE_VAULT contract.
		// However, the block.coinbase is set to 0x0, rather than the vault contract.
		// It would be nice for l2geth to populate the appropriate coinbase so we're robust against changes to the vault addresss.
		loadedTxs[i].Miner = sequencerFeeVaultAddr
		loadedTxs[i].Receipt = receipt
		loadedTxs[i].Status = receipt.Status == 1

		// Continue if calls does not exist (occurs at genesis)
		if !addTraces {
			continue
		}

		loadedTxs[i].Trace = traces[i]
	}

	block := types.NewBlockWithHeader(head).WithBody(
		txs,
		nil, // Sequencer blocks do not have uncles with instant confirmation
	)

	blockIdentifier := &RosettaTypes.BlockIdentifier{
		Hash:  block.Hash().String(),
		Index: block.Number().Int64(),
	}

	parentBlockIdentifier := blockIdentifier
	if blockIdentifier.Index != GenesisBlockIndex {
		parentBlockIdentifier = &RosettaTypes.BlockIdentifier{
			Hash:  block.ParentHash().Hex(),
			Index: blockIdentifier.Index - 1,
		}
	}

	populatedTxs, err := ec.populateTransactions(ctx, blockIdentifier, block, loadedTxs)
	if err != nil {
		return nil, err
	}

	return &RosettaTypes.Block{
		BlockIdentifier:       blockIdentifier,
		ParentBlockIdentifier: parentBlockIdentifier,
		Timestamp:             convertTime(block.Time()),
		Transactions:          populatedTxs,
	}, nil
}

//nolint:unparam
func (ec *Client) populateTransactions(
	ctx context.Context,
	blockIdentifier *RosettaTypes.BlockIdentifier,
	block *types.Block,
	loadedTransactions []*legacyTransaction,
) ([]*RosettaTypes.Transaction, error) {
	transactions := make(
		[]*RosettaTypes.Transaction,
		len(block.Transactions()),
	)

	for i, tx := range loadedTransactions {
		if tx.From != nil && tx.Transaction != nil && tx.Transaction.To() != nil {
			from, to := tx.From.Hex(), tx.Transaction.To().Hex()

			// These are tx across L1 and L2. These cost zero gas as they're manufactured by the sequencer
			if from == zeroAddr {
				tx.FeeAmount.SetUint64(0)
			} else if (to == gasPriceOracleAddr.Hex()) && (from == gasPriceOracleOwnerMainnet.Hex() || from == gasPriceOracleOwnerKovan.Hex() || from == gasPriceOracleOwnerGoerli.Hex()) {
				// The sequencer doesn't charge the owner of the gpo.
				// Set the fee mount to zero to not affect gpo owner balances
				tx.FeeAmount.SetUint64(0)
			}
		}

		transaction, err := ec.populateTransaction(ctx, block, tx)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot parse %s", err, tx.Transaction.Hash().Hex())
		}
		transactions[i] = transaction
	}

	return transactions, nil
}

func (ec *Client) populateTransaction(
	ctx context.Context,
	block *types.Block,
	tx *legacyTransaction,
) (*RosettaTypes.Transaction, error) {
	ops := []*RosettaTypes.Operation{}

	// Compute fee operations
	feeOps := feeOps(tx)
	patchFeeOps(ec.p.ChainID, block, tx.Transaction, feeOps)
	ops = append(ops, feeOps...)

	erc20TokenOps, err := ec.erc20TokenOps(ctx, block, tx, len(ops))
	if err != nil {
		return nil, err
	}
	ops = append(ops, erc20TokenOps...)

	traces := flattenTraces(tx.Trace, []*FlatCall{})

	traceOps := traceOps(block, traces, len(ops))
	ops = append(ops, traceOps...)

	// Marshal receipt and trace data
	// TODO: replace with marshalJSONMap (used in `services`)
	receiptBytes, err := tx.Receipt.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("%w: cannot marshal receipt json", err)
	}

	var receiptMap map[string]interface{}
	if err := json.Unmarshal(receiptBytes, &receiptMap); err != nil {
		return nil, fmt.Errorf("%w: cannot unmarshal receipt bytes into map", err)
	}

	populatedTransaction := &RosettaTypes.Transaction{
		TransactionIdentifier: &RosettaTypes.TransactionIdentifier{
			Hash: tx.Transaction.Hash().Hex(),
		},
		Operations: ops,
		Metadata: map[string]interface{}{
			"gas_limit": hexutil.EncodeUint64(tx.Transaction.Gas()),
			"gas_price": hexutil.EncodeBig(tx.Transaction.GasPrice()),
			"receipt":   receiptMap,
		},
	}

	return populatedTransaction, nil
}
