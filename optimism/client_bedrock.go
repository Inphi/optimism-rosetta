package optimism

import (
	"context"
	"encoding/json"
	"math/big"

	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
)

// IsPreBedrock returns if the given block number is before the bedrock block.
func (c *Client) IsPreBedrock(b *big.Int) bool {
	return c.bedrockBlock == nil || b.Cmp(c.bedrockBlock) < 0
}

// SuggestGasPrice retrieves the currently suggested gas price
func (ec *Client) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, "eth_maxPriorityFeePerGas"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// BaseFee returns the current base fee per gas
func (ec *Client) BaseFee(ctx context.Context) (*big.Int, error) {
	type header struct {
		BaseFee hexutil.Big `json:"baseFeePerGas"`
	}
	var head *header
	if err := ec.c.CallContext(ctx, &head, "eth_getBlockByNumber", "latest", false); err != nil {
		return nil, err
	}
	if head == nil {
		return nil, ethereum.NotFound
	}
	return head.BaseFee.ToInt(), nil
}

// rpcBedrockBlock is a post-bedrock block.
type rpcBedrockBlock struct {
	Hash         EthCommon.Hash          `json:"hash"`
	Transactions []BedrockRPCTransaction `json:"transactions"`
	UncleHashes  []EthCommon.Hash        `json:"uncles"`
}

// BedrockRPCTransaction is a post-bedrock transaction.
type BedrockRPCTransaction struct {
	Tx InnerBedrockTransaction `json:"tx"`
	TxExtraInfo
}

// UnmarshalJSON unmarshals an [BedrockRPCTransaction] from bytes.
func (tx *BedrockRPCTransaction) UnmarshalJSON(msg []byte) error {
	var innerTx transaction
	if err := json.Unmarshal(msg, &innerTx); err != nil {
		return err
	}
	tx.Tx = &innerTx
	return json.Unmarshal(msg, &tx.TxExtraInfo)
}

type TxExtraInfo struct {
	BlockNumber *string            `json:"blockNumber,omitempty"`
	BlockHash   *EthCommon.Hash    `json:"blockHash,omitempty"`
	From        *EthCommon.Address `json:"from,omitempty"`
	TxHash      *EthCommon.Hash    `json:"hash,omitempty"`
}

// parseBedrockBlock returns a [EthTypes.Header] and [rpcBedrockBlock] for a given block or a respective error.
func (c *Client) parseBedrockBlock(raw *json.RawMessage) (
	*EthTypes.Header,
	*rpcBedrockBlock,
	error,
) {
	// Decode bedrock header and transactions
	var head EthTypes.Header
	var body rpcBedrockBlock
	if err := json.Unmarshal(*raw, &head); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(*raw, &body); err != nil {
		return nil, nil, err
	}
	return &head, &body, nil
}

// RosettaTxReceipt is a Rosetta-compatible receipt type.
type RosettaTxReceipt struct {
	Type           uint8 `json:"type,omitempty"`
	GasPrice       *big.Int
	GasUsed        *big.Int
	TransactionFee *big.Int
	Logs           []*EthTypes.Log
	RawMessage     json.RawMessage
}

// bedrockTransaction is a post-bedrock transaction type.
type bedrockTransaction struct {
	Transaction InnerBedrockTransaction
	From        *EthCommon.Address
	BlockNumber *string
	BlockHash   *EthCommon.Hash
	TxHash      *EthCommon.Hash // may not equal Transaction.Hash() due to state sync indicator
	FeeAmount   *big.Int
	FeeBurned   *big.Int // nil if no fees were burned
	Miner       string
	Status      bool

	Trace    []*FlatCall
	RawTrace json.RawMessage
	Receipt  *RosettaTxReceipt

	BaseFee *big.Int
}

// L1ToL2DepositType is the transaction type for L1ToL2 deposits.
const L1ToL2DepositType = 126 // (126)

// IsDepositTx returns true if the transaction is a deposit tx type.
func (bt *bedrockTransaction) IsDepositTx() bool {
	return bt.Transaction.GetType() == L1ToL2DepositType
}

// LoadTransaction constructs a [bedrockTransaction] from a [BedrockRPCTransaction].
//
//nolint:golint
func (tx *BedrockRPCTransaction) LoadTransaction() *bedrockTransaction {
	ethTx := &bedrockTransaction{
		Transaction: tx.Tx,
		From:        tx.TxExtraInfo.From,
		TxHash:      tx.TxHash,
		BlockNumber: tx.TxExtraInfo.BlockNumber,
		BlockHash:   tx.TxExtraInfo.BlockHash,
	}
	return ethTx
}
