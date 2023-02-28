package optimism

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const TopicsInErc20Transfer = 3

// getParsedBedrockBlock constructs a [RosettaTypes.Block] from a raw block response.
//
//nolint:gocognit
func (ec *Client) getParsedBedrockBlock(
	ctx context.Context,
	raw *json.RawMessage,
) (
	*RosettaTypes.Block,
	error,
) {
	head, body, err := ec.parseBedrockBlock(raw)
	if err != nil {
		return nil, err
	}

	// Use a client option here to fetch traces from either debug_traceBlockByHash or debug_traceTransaction
	var m map[string][]*FlatCall
	addTraces := head.Number.Int64() != GenesisBlockIndex
	if addTraces {
		if ec.traceByBlock {
			m, err = ec.TraceBlockByHash(ctx, body.Hash, body.Transactions)
			if err != nil {
				return nil, err
			}
		} else {
			m, err = ec.TraceTransactions(ctx, body.Hash, body.Transactions)
			if err != nil {
				return nil, err
			}
		}
	}

	// Convert all txs to loaded txs
	txs := make([]InnerBedrockTransaction, len(body.Transactions))
	loadedTxs := make([]*bedrockTransaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		txs[i] = tx.Tx

		loadedTxs[i] = tx.LoadTransaction()
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
			// We have to extract the status from the raw receipt since RosettaTxReceipt has no status field
			status, _ := ExtractStatus(receipts[i])
			tx.Status = status == 1
		}

		// EIP-1559 Support
		if tx.BaseFee != nil {
			tx.FeeBurned = new(big.Int).Mul(tx.Receipt.GasUsed, tx.BaseFee)
		} else {
			tx.FeeBurned = baseFee
		}
	}

	blockIdentifier := &RosettaTypes.BlockIdentifier{
		Index: head.Number.Int64(),
		Hash:  head.Hash().String(),
	}

	parentBlockIdentifier := blockIdentifier
	if blockIdentifier.Index != GenesisBlockIndex {
		parentBlockIdentifier = &RosettaTypes.BlockIdentifier{
			Hash:  head.ParentHash.Hex(),
			Index: blockIdentifier.Index - 1,
		}
	}

	// Populate transactions
	rosettaTxs := make([]*RosettaTypes.Transaction, len(loadedTxs))
	for i, tx := range loadedTxs {
		transaction, err := ec.populateBedrockTransaction(ctx, head, tx)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot parse %s", err, tx.Transaction.Hash().Hex())
		}
		rosettaTxs[i] = transaction
	}

	return &RosettaTypes.Block{
		BlockIdentifier:       blockIdentifier,
		ParentBlockIdentifier: parentBlockIdentifier,
		Timestamp:             convertTime(head.Time),
		Transactions:          rosettaTxs,
		Metadata:              nil,
	}, nil
}

// populateBedrockTransaction populates a Rosetta transaction from a bedrock transaction.
func (ec *Client) populateBedrockTransaction(
	ctx context.Context,
	head *EthTypes.Header,
	tx *bedrockTransaction,
) (*RosettaTypes.Transaction, error) {
	ops, err := ec.ParseOps(tx)
	if err != nil {
		return nil, err
	}

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
				currency, err := ec.currencyFetcher.FetchCurrency(ctx, head.Number.Uint64(), log.Address.Hex())
				if err != nil {
					return nil, err
				}

				if currency.Symbol == UnknownERC20Symbol || currency.Symbol == defaultERC20Symbol {
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

	// var traceList []interface{}
	// for _, trace := range tx.Trace {
	// 	traceBytes, _ := json.Marshal(trace)
	// 	var traceMap map[string]interface{}
	// 	if err := json.Unmarshal(traceBytes, &traceMap); err != nil {
	// 		return nil, err
	// 	}
	// 	traceList = append(traceList, traceMap)
	// }

	populatedTransaction := &RosettaTypes.Transaction{
		TransactionIdentifier: &RosettaTypes.TransactionIdentifier{
			Hash: tx.TxHash.String(),
		},
		Operations: ops,
		Metadata: map[string]interface{}{
			"gas_limit": hexutil.EncodeUint64(tx.Transaction.Gas()),
			"gas_price": hexutil.EncodeBig(tx.Transaction.GasPrice()),
			"receipt":   receiptMap,
			// Don't include the trace list in the metadata since it can be very large
			// "trace":     traceList,
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
			Amount:  Erc20Amount(transferLog.Data, contractAddress, *currency, true),
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
		Amount:  Erc20Amount(transferLog.Data, contractAddress, *currency, true),
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
