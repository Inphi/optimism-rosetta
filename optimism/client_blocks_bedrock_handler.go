package optimism

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/coinbase/rosetta-sdk-go/utils"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var TopicsInErc20Transfer = 3

// geth traces types
type rpcCall struct {
	Result *Call `json:"result"`
}

// TraceBlockByHash returns the Transaction traces of all transactions in the block
func (ec *Client) TraceBlockByHash(
	ctx context.Context,
	blockHash EthCommon.Hash,
	txs []BedrockRPCTransaction,
) (map[string][]*FlatCall, error) {
	if err := ec.traceSemaphore.Acquire(ctx, semaphoreTraceWeight); err != nil {
		return nil, err
	}
	defer ec.traceSemaphore.Release(semaphoreTraceWeight)

	var calls []*rpcCall
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, "debug_traceBlockByHash", blockHash, ec.tc)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil, err
	}
	m := make(map[string][]*FlatCall)
	for i, tx := range calls {
		if tx.Result.Type == "" {
			// ignore calls with an empty type
			continue
		}
		flatCalls := FlattenTraces(tx.Result, []*FlatCall{})
		// Ethereum native traces are guaranteed to return all transactions
		txHash := txs[i].TxExtraInfo.BlockHash.Hex()
		if txHash == "" {
			return nil, fmt.Errorf("could not get %dth tx hash for block %s", i, blockHash.Hex())
		}
		m[txHash] = flatCalls
	}
	return m, nil
}

// flattenTraces recursively flattens all traces.
func FlattenTraces(data *Call, flattened []*FlatCall) []*FlatCall {
	if data == nil {
		return flattened
	}
	results := append(flattened, data.flatten()) //nolint
	for _, child := range data.Calls {
		// Ensure all children of a reverted call
		// are also reverted!
		if data.Revert {
			child.Revert = true

			// Copy error message from parent
			// if child does not have one
			if len(child.ErrorMessage) == 0 {
				child.ErrorMessage = data.ErrorMessage
			}
		}

		children := FlattenTraces(child, flattened)
		results = append(results, children...)
	}
	return results
}

// getParsedBedrockBlock constructs a [RosettaTypes.Block] from the
func (ec *Client) getParsedBedrockBlock(
	ctx context.Context,
	blockMethod string,
	args ...interface{},
) (
	*RosettaTypes.Block,
	error,
) {
	fmt.Printf("Inside getParsedBedrockBlock...\n")
	head, body, err := ec.getBedrockBlock(ctx, blockMethod, args...)
	fmt.Printf("Got bedrock block and header, err: %v\n", err)
	if err != nil {
		return nil, err
	}

	fmt.Print("Tracing block by hash...\n")
	var m map[string][]*FlatCall
	var addTraces bool
	if head.Number.Int64() != GenesisBlockIndex {
		addTraces = true
		m, err = ec.TraceBlockByHash(ctx, body.Hash, body.Transactions)
		fmt.Printf("Got block traces, m: %v\n err: %v\n", m, err)

		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%w: could not get receipts for %x", err, body.Hash[:])
	}

	// Convert all txs to loaded txs
	txs := make([]*EthTypes.Transaction, len(body.Transactions))
	loadedTxs := make([]*bedrockTransaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		fmt.Printf("Loading transaction %d: %+v\n", i, tx)
		txs[i] = tx.Tx

		loadedTxs[i] = tx.LoadedTransaction()
		loadedTxs[i].Transaction = txs[i]
		loadedTxs[i].BaseFee = head.BaseFee
		loadedTxs[i].Miner = MustChecksum(head.Coinbase.Hex())

		// Continue if calls does not exist (occurs at genesis)
		if !addTraces {
			continue
		}

		// Find traces based on Tx Hash
		hsh := loadedTxs[i].TxHash.Hex()
		if flattenedCalls, ok := m[hsh]; ok {
			loadedTxs[i].Trace = flattenedCalls
		}
	}

	// Construct the block
	block := EthTypes.NewBlockWithHeader(head).WithBody(
		txs,
		nil, // sequencer blocks don't have uncles
	)

	if err != nil {
		return nil, fmt.Errorf("%w: geth error", err)
	}

	// Get all transaction receipts
	var baseFee *big.Int
	if len(body.Transactions) > 0 {
		baseFee = loadedTxs[0].BaseFee
	}
	receipts, err := ec.getBedrockBlockReceipts(ctx, body.Hash, body.Transactions, baseFee)
	if err != nil {
		return nil, fmt.Errorf("%w: could not get receipts for %x", err, body.Hash[:])
	}
	for i, tx := range loadedTxs {
		if receipts != nil {
			tx.Receipt = receipts[i]
			if tx.Receipt.TransactionFee != nil {
				tx.FeeAmount = tx.Receipt.TransactionFee
			} else {
				tx.FeeAmount = big.NewInt(0)
			}
			// TODO: RosettaTxReceipt has no "Status"
			// tx.Status = receipts[i].Status == 1
		}

		// EIP-1559 Support
		if tx.BaseFee != nil {
			tx.FeeBurned = new(big.Int).Mul(tx.Receipt.GasUsed, tx.BaseFee)
		} else {
			tx.FeeBurned = baseFee
		}
	}

	blockIdentifier := &RosettaTypes.BlockIdentifier{
		Index: block.Number().Int64(),
		Hash:  block.Hash().String(),
	}

	parentBlockIdentifier := blockIdentifier
	if blockIdentifier.Index != GenesisBlockIndex {
		parentBlockIdentifier = &RosettaTypes.BlockIdentifier{
			Hash:  block.ParentHash().Hex(),
			Index: blockIdentifier.Index - 1,
		}
	}

	// TODO: Populate cross chain txs

	transactions, err := ec.populateBedrockTransactions(
		ctx,
		blockIdentifier,
		block,
		loadedTxs,
	)

	if err != nil {
		return nil, fmt.Errorf("%w: unable to populate transactions", err)
	}

	return &RosettaTypes.Block{
		BlockIdentifier:       blockIdentifier,
		ParentBlockIdentifier: parentBlockIdentifier,
		Timestamp:             int64(block.Time() * utils.MillisecondsInSecond),
		Transactions:          transactions,
		Metadata:              nil,
	}, nil
}

//nolint:unparam
func (ec *Client) populateBedrockTransactions(
	ctx context.Context,
	blockIdentifier *RosettaTypes.BlockIdentifier,
	block *EthTypes.Block,
	loadedTransactions []*bedrockTransaction,
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

		transaction, err := ec.populateBedrockTransaction(ctx, block, tx)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot parse %s", err, tx.Transaction.Hash().Hex())
		}
		transactions[i] = transaction
	}

	return transactions, nil
}

// populateBedrockTransaction populates a Rosetta transaction from a bedrock transaction.
func (ec *Client) populateBedrockTransaction(
	ctx context.Context,
	block *EthTypes.Block,
	tx *bedrockTransaction,
) (*RosettaTypes.Transaction, error) {
	ops := []*RosettaTypes.Operation{}

	keccak := crypto.Keccak256([]byte(erc20TransferEventLogTopics))
	encodedTransferMethod := hexutil.Encode(keccak)

	var receiptLogs []*EthTypes.Log
	if tx.Receipt != nil {
		receiptLogs = tx.Receipt.Logs
	}

	// Compute tx operations via tx.Receipt logs for ERC20 transfers
	// if Filter == false, we record every ERC20 tokens
	for _, log := range receiptLogs {
		// If this isn't an ERC20 transfer, skip
		if !BedrockContainsTopic(log, encodedTransferMethod) {
			continue
		}
		if !ec.filterTokens || (ec.filterTokens && ec.supportedTokens[log.Address.String()]) {
			switch len(log.Topics) {
			case TopicsInErc20Transfer:
				currency, err := ec.currencyFetcher.FetchCurrency(ctx, block.NumberU64(), log.Address.Hex())
				if err != nil {
					return nil, err
				}

				if currency.Symbol == UnknownERC20Symbol {
					continue
				}
				erc20Ops := Erc20Ops(log, currency, int64(len(ops)))
				ops = append(ops, erc20Ops...)
			default:
			}
		}
	}

	// Marshal receipt and trace data
	receiptMap, err := MarshalJSONMap(tx.Receipt)
	if err != nil {
		return nil, err
	}

	var traceList []map[string]interface{}
	for _, trace := range tx.Trace {
		traceBytes, _ := json.Marshal(trace)
		var traceMap map[string]interface{}
		if err := json.Unmarshal(traceBytes, &traceMap); err != nil {
			return nil, err
		}
		traceList = append(traceList, traceMap)
	}

	populatedTransaction := &RosettaTypes.Transaction{
		TransactionIdentifier: &RosettaTypes.TransactionIdentifier{
			Hash: tx.TxHash.String(),
		},
		Operations: ops,
		Metadata: map[string]interface{}{
			"gas_limit": hexutil.EncodeUint64(tx.Transaction.Gas()),
			"gas_price": hexutil.EncodeBig(tx.Transaction.GasPrice()),
			"receipt":   receiptMap,
			"trace":     traceList,
		},
	}

	return populatedTransaction, nil
}

// Erc20Ops returns a list of erc20 operations parsed from the log from a transaction receipt
func Erc20Ops(
	transferLog *EthTypes.Log,
	currency *RosettaTypes.Currency,
	opsLen int64,
) []*RosettaTypes.Operation {
	ops := []*RosettaTypes.Operation{}

	contractAddress := transferLog.Address
	addressFrom := transferLog.Topics[1]
	addressTo := transferLog.Topics[2]

	if addressFrom.Hex() == zeroAddress {
		mintOp := RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: opsLen,
			},
			Status:  RosettaTypes.String(SuccessStatus),
			Type:    ERC20MintOpType,
			Amount:  Erc20Amount(transferLog.Data, contractAddress, *currency, false),
			Account: Account(ConvertEVMTopicHashToAddress(&addressTo)),
		}
		ops = append(ops, &mintOp)
		return ops
	}

	if addressTo.Hex() == zeroAddress {
		burnOp := RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: opsLen,
			},
			Status:  RosettaTypes.String(SuccessStatus),
			Type:    ERC20BurnOpType,
			Amount:  Erc20Amount(transferLog.Data, contractAddress, *currency, false),
			Account: Account(ConvertEVMTopicHashToAddress(&addressFrom)),
		}
		ops = append(ops, &burnOp)
		return ops
	}
	sendingOp := RosettaTypes.Operation{
		OperationIdentifier: &RosettaTypes.OperationIdentifier{
			Index: opsLen,
		},
		Status:  RosettaTypes.String(SuccessStatus),
		Type:    ERC20TransferOpType,
		Amount:  Erc20Amount(transferLog.Data, contractAddress, *currency, false),
		Account: Account(ConvertEVMTopicHashToAddress(&addressFrom)),
	}
	receiptOp := RosettaTypes.Operation{
		OperationIdentifier: &RosettaTypes.OperationIdentifier{
			Index: opsLen + 1,
		},
		Status:  RosettaTypes.String(SuccessStatus),
		Type:    ERC20TransferOpType,
		Amount:  Erc20Amount(transferLog.Data, contractAddress, *currency, false),
		Account: Account(ConvertEVMTopicHashToAddress(&addressTo)),
		RelatedOperations: []*RosettaTypes.OperationIdentifier{
			{
				Index: opsLen,
			},
		},
	}
	ops = append(ops, &sendingOp)
	ops = append(ops, &receiptOp)

	return ops
}

func Account(address *EthCommon.Address) *RosettaTypes.AccountIdentifier {
	if address == nil {
		return nil
	}
	return &RosettaTypes.AccountIdentifier{
		Address: address.String(),
	}
}

func Erc20Amount(
	bytes []byte,
	addr EthCommon.Address,
	currency RosettaTypes.Currency,
	sender bool,
) *RosettaTypes.Amount {
	value := EthCommon.BytesToHash(bytes).Big()

	if sender {
		value = new(big.Int).Neg(value)
	}

	return &RosettaTypes.Amount{
		Value:    value.String(),
		Currency: &currency,
	}
}

// ConvertEVMTopicHashToAddress uses the last 20 bytes of a common.Hash to create a common.Address
func ConvertEVMTopicHashToAddress(hash *EthCommon.Hash) *EthCommon.Address {
	if hash == nil {
		return nil
	}
	address := EthCommon.BytesToAddress(hash[12:32])
	return &address
}

// BedrockContainsTopic checks if a bedrock log contains a topic
func BedrockContainsTopic(log *EthTypes.Log, topic string) bool {
	for _, t := range log.Topics {
		hex := t.Hex()
		if hex == topic {
			return true
		}
	}
	return false
}

// MarshalJSONMap converts an interface into a map[string]interface{}.
func MarshalJSONMap(i interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}

	return m, nil
}

// UnmarshalJSONMap converts map[string]interface{} into a interface{}.
func UnmarshalJSONMap(m map[string]interface{}, i interface{}) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}

	return json.Unmarshal(b, i)
}
