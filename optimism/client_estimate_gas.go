package optimism

import (
	"context"

	OptimismEth "github.com/ethereum-optimism/optimism/l2geth"
	OptimismHexUtil "github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
)

// EstimateGas retrieves the currently gas limit
func (ec *Client) EstimateGas(ctx context.Context, msg OptimismEth.CallMsg) (uint64, error) {
	arg := map[string]interface{}{
		"from": msg.From,
		"to":   msg.To,
	}
	if len(msg.Data) > 0 {
		arg["data"] = OptimismHexUtil.Bytes(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = (*OptimismHexUtil.Big)(msg.Value)
	}
	if msg.Gas != 0 {
		arg["gas"] = OptimismHexUtil.Uint64(msg.Gas)
	}
	if msg.GasPrice != nil {
		arg["gasPrice"] = (*OptimismHexUtil.Big)(msg.GasPrice)
	}

	var hex OptimismHexUtil.Uint64
	err := ec.c.CallContext(ctx, &hex, "eth_estimateGas", arg)
	if err != nil {
		return 0, err
	}
	return uint64(hex), nil
}
