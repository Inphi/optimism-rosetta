// Copyright 2023 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package optimism

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	OptimismEth "github.com/ethereum-optimism/optimism/l2geth"
	OptimismCommon "github.com/ethereum-optimism/optimism/l2geth/common"
	OptimismHexUtil "github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	OptimismRpc "github.com/ethereum-optimism/optimism/l2geth/rpc"
	OptimismArtifacts "github.com/inphi/optimism-rosetta/optimism/utilities/artifacts"
)

// Balance returns the balance of a *RosettaTypes.AccountIdentifier
// at a *RosettaTypes.PartialBlockIdentifier.
// The OP Token and ETH balances will be returned if currencies is unspecified
//
//nolint:gocognit
func (ec *Client) Balance(
	ctx context.Context,
	account *RosettaTypes.AccountIdentifier,
	block *RosettaTypes.PartialBlockIdentifier,
	currencies []*RosettaTypes.Currency,
) (*RosettaTypes.AccountBalanceResponse, error) {
	var raw json.RawMessage
	if block != nil {
		if block.Hash != nil {
			if err := ec.c.CallContext(ctx, &raw, "eth_getBlockByHash", block.Hash, false); err != nil {
				return nil, err
			}
		}
		if block.Hash == nil && block.Index != nil {
			if err := ec.c.CallContext(
				ctx,
				&raw,
				"eth_getBlockByNumber",
				OptimismHexUtil.EncodeUint64(uint64(*block.Index)),
				false,
			); err != nil {
				return nil, err
			}
		}
	} else {
		if err := ec.c.CallContext(ctx, &raw, "eth_getBlockByNumber", toBlockNumArg(nil), false); err != nil {
			return nil, err
		}
	}
	if len(raw) == 0 {
		return nil, OptimismEth.NotFound
	}

	// Rather than assume we're dealing with a legacy/bedrock header, just get the common fields we need
	type numberHeader struct {
		Number *OptimismHexUtil.Big `json:"number"`
		Hash   OptimismCommon.Hash  `json:"hash"`
	}
	var head *numberHeader
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}

	var (
		balance OptimismHexUtil.Big
		nonce   OptimismHexUtil.Uint64
		code    string
	)

	blockNum := OptimismHexUtil.EncodeUint64(head.Number.ToInt().Uint64())
	reqs := []OptimismRpc.BatchElem{
		{Method: "eth_getBalance", Args: []interface{}{account.Address, blockNum}, Result: &balance},
		{Method: "eth_getTransactionCount", Args: []interface{}{account.Address, blockNum}, Result: &nonce},
		{Method: "eth_getCode", Args: []interface{}{account.Address, blockNum}, Result: &code},
	}
	if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
		return nil, err
	}
	for i := range reqs {
		if reqs[i].Error != nil {
			return nil, reqs[i].Error
		}
	}

	nativeBalance := &RosettaTypes.Amount{
		Value:    balance.ToInt().String(),
		Currency: Currency,
	}

	var balances []*RosettaTypes.Amount
	for _, curr := range currencies {
		if reflect.DeepEqual(curr, Currency) {
			balances = append(balances, nativeBalance)
			continue
		}

		contractAddress := fmt.Sprintf("%s", curr.Metadata[ContractAddressKey])
		_, ok := ChecksumAddress(contractAddress)
		if !ok {
			return nil, fmt.Errorf("invalid contract address %s", contractAddress)
		}

		balance, err := ec.getBalance(ctx, account.Address, blockNum, contractAddress)
		if err != nil {
			return nil, fmt.Errorf("err encountered for currency %s, token address %s; %v", curr.Symbol, contractAddress, err)
		}
		balances = append(balances, &RosettaTypes.Amount{
			Value:    balance,
			Currency: curr,
		})
	}

	if len(currencies) == 0 {
		opTokenBalance, err := ec.getBalance(ctx, account.Address, blockNum, opTokenContractAddress.String())
		if err != nil {
			return nil, fmt.Errorf("err getting OP token balance; %v", err)
		}
		balances = append(balances, nativeBalance, &RosettaTypes.Amount{
			Value:    opTokenBalance,
			Currency: OPTokenCurrency,
		})
	}

	return &RosettaTypes.AccountBalanceResponse{
		Balances: balances,
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  head.Hash.Hex(),
			Index: head.Number.ToInt().Int64(),
		},
		Metadata: map[string]interface{}{
			"nonce": int64(nonce),
			"code":  code,
		},
	}, nil
}

func (ec *Client) getBalance(ctx context.Context, accountAddress string, blockNum string, contractAddress string) (string, error) {
	erc20Data, err := OptimismArtifacts.ERC20ABI.Pack("balanceOf", OptimismCommon.HexToAddress(accountAddress))
	if err != nil {
		return "", err
	}
	encodedERC20Data := OptimismHexUtil.Encode(erc20Data)

	callParams := map[string]string{
		"to":   contractAddress,
		"data": encodedERC20Data,
	}
	var resp string
	if err := ec.c.CallContext(ctx, &resp, "eth_call", callParams, blockNum); err != nil {
		return "", err
	}
	// "0x" may be returned when retrieving balances of historical state that have been pruned by non-archival nodes
	if resp == "0x" {
		return "0", nil
	}
	balance, err := decodeHexData(resp)
	if err != nil {
		return "", err
	}

	return balance.String(), nil
}
