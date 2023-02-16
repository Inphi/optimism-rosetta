package optimism

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
)

// IsPreBedrock returns if the given block number is before the bedrock block.
func (c *Client) IsPreBedrock(b *big.Int) bool {
	return c.bedrockBlock == nil || b.Cmp(c.bedrockBlock) < 0
}

// rpcBedrockBlock is a post-bedrock block.
type rpcBedrockBlock struct {
	Hash         EthCommon.Hash          `json:"hash"`
	Transactions []BedrockRPCTransaction `json:"transactions"`
	UncleHashes  []EthCommon.Hash        `json:"uncles"`
}

// EthTypes.Transaction contains TxData, which is DynamicFeeTx:
// https://github.com/ethereum/go-ethereum/blob/980b7682b474db61ecbd78171e7cacfec8214048
// /core/types/dynamic_fee_tx.go#L25
type BedrockRPCTransaction struct {
	Tx *EthTypes.Transaction `json:"tx"`
	TxExtraInfo
}

// UnmarshalJSON unmarshals an [BedrockRPCTransaction] from bytes.
func (tx *BedrockRPCTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.Tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.TxExtraInfo)
}

// LoadedTransaction converts an [rpcTransaction] to a bedrockTransaction.
//
//nolint:golint
func (tx *BedrockRPCTransaction) LoadedTransaction() *bedrockTransaction {
	ethTx := bedrockTransaction{
		Transaction: tx.Tx,
		From:        tx.TxExtraInfo.From,
		BlockNumber: tx.TxExtraInfo.BlockNumber,
		BlockHash:   tx.TxExtraInfo.BlockHash,
	}
	return &ethTx
}

type TxExtraInfo struct {
	BlockNumber *string            `json:"blockNumber,omitempty"`
	BlockHash   *EthCommon.Hash    `json:"blockHash,omitempty"`
	From        *EthCommon.Address `json:"from,omitempty"`
	TxHash      *EthCommon.Hash    `json:"hash,omitempty"`
}

// getBedrockBlock returns a [EthTypes.Header] and [rpcBedrockBlock] for a given block or a respective error.
func (c *Client) getBedrockBlock(
	ctx context.Context,
	blockMethod string,
	args ...interface{},
) (
	*EthTypes.Header,
	*rpcBedrockBlock,
	error,
) {
	var raw json.RawMessage
	err := c.c.CallContext(ctx, &raw, blockMethod, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: block fetch failed", err)
	} else if len(raw) == 0 {
		return nil, nil, ethereum.NotFound
	}

	// Decode bedrock header and transactions
	fmt.Println("Got raw block, decoding EthTypes.Header and rpcBedrockBlock...")
	var head EthTypes.Header
	var body rpcBedrockBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, nil, err
	}
	fmt.Println("Successfully decoded header")
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, nil, err
	}
	fmt.Println("Successfully decoded body")
	return &head, &body, nil
}
