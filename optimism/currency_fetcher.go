// Copyright 2021 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package optimism

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	"github.com/ethereum/go-ethereum/accounts/abi"

	lru "github.com/hashicorp/golang-lru"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/inphi/optimism-rosetta/optimism/utilities/artifacts"
)

const (
	defaultCacheSize = 100

	defaultERC20Decimals = 0

	defaultERC20Symbol = "UNKNOWN"
)

var ErrBadCurrency = errors.New("bad currency")

// CurrencyFetcher interface describes a struct that can fetch the details of
// an Ethereum-based token given its contract address.
type CurrencyFetcher interface {
	FetchCurrency(ctx context.Context, blockNum uint64, contractAddress string) (*RosettaTypes.Currency, error)
}

// ERC20CurrencyFetcher type has a global currencyCache (lru) to cache results of fetching currency details,
// as well as a GraphQL client (required for getting currency details).
type ERC20CurrencyFetcher struct {
	currencyCache *lru.Cache

	c JSONRPC
}

// parseStringReturn parses data for ABI functions that return a single string
func parseStringReturn(parsedABI abi.ABI, methodName string, data []byte) (string, error) {
	stringRes, err := parsedABI.Unpack(methodName, data)
	if err != nil {
		return "", err
	}

	out0 := stringRes[0].(string)
	return out0, nil
}

// parseIntReturn parses data for the functions of ERC20s that return ints
func parseIntReturn(parsedABI abi.ABI, methodName string, data []byte) (*big.Int, error) {
	intRes, err := parsedABI.Unpack(methodName, data)
	if err != nil {
		return nil, err
	}

	out0 := *abi.ConvertType(intRes[0], new(*big.Int)).(**big.Int)
	return out0, nil
}

// FetchCurrency is a helper function that takes in a contract address (ERC20) and returns a Currency object
// with details such as the symbol and # of decimal places. This method uses RPC calls to fetch such data.
// Because the contractAddress param is checksummed prior to invocation, we assume it is valid.
// We make use of an LRU cache to prevent repeatedly fetching currency details.
//
// There are a few failure cases that this logic accounts for. If any contract call returns an empty value ("0x"),
// we fall back on default values. Additionally, in the specific case of the symbol, if an empty symbol is returned, we
// again fall back on the default symbol value.
//
// Note: any returned data payload with the prefix `0x4e487b71` are the first four bytes of keccak256(Panic(uint256))
// If we encounter a failure while fetching currency details, we return a default value.
func (ecf ERC20CurrencyFetcher) FetchCurrency(
	ctx context.Context,
	blockNum uint64,
	contractAddress string,
) (*RosettaTypes.Currency, error) {
	if cachedCurrency, ok := ecf.currencyCache.Get(contractAddress); ok {
		return cachedCurrency.(*RosettaTypes.Currency), nil
	}

	decimalsData, err := artifacts.ERC20ABI.Pack("decimals")
	if err != nil {
		return nil, err
	}
	encodedDecimalsData := hexutil.Encode(decimalsData)

	symbolData, err := artifacts.ERC20ABI.Pack("symbol")
	if err != nil {
		return nil, err
	}
	encodedSymbolData := hexutil.Encode(symbolData)

	var decimalsResult string
	var symbolResult string
	blockNumHex := hexutil.EncodeUint64(blockNum)
	reqs := []rpc.BatchElem{
		{Method: "eth_call", Args: []interface{}{map[string]string{"to": contractAddress, "data": encodedDecimalsData}, blockNumHex}, Result: &decimalsResult},
		{Method: "eth_call", Args: []interface{}{map[string]string{"to": contractAddress, "data": encodedSymbolData}, blockNumHex}, Result: &symbolResult},
	}
	if err := ecf.c.BatchCallContext(ctx, reqs); err != nil {
		return nil, err
	}
	for i := range reqs {
		if reqs[i].Error != nil {
			return nil, reqs[i].Error
		}
	}

	decodedDecimals, err := hexutil.Decode(decimalsResult)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to decode decimals", ErrBadCurrency)
	}
	var decimalsBigInt *big.Int
	// If the decodedDecimals byte slice has a non-zero length, parse it as an Int. Otherwise, let decimals default to 0.
	if len(decodedDecimals) > 0 {
		decimalsBigInt, err = parseIntReturn(artifacts.ERC20ABI, "decimals", decodedDecimals)

		if decimalsBigInt.Cmp(big.NewInt(0x7FFFFFFF)) == 1 {
			// if it cannot be casted into int32 (due to overflow), default to 0
			decimalsBigInt = big.NewInt(0)
		}

		if err != nil {
			return nil, fmt.Errorf("%w: unable to parse decimals: %s", ErrBadCurrency, err.Error())
		}
	} else {
		decimalsBigInt = big.NewInt(defaultERC20Decimals)
	}

	decodedString, err := hexutil.Decode(symbolResult)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to decode symbol: %s", ErrBadCurrency, err.Error())
	}
	var symbolString string
	// Only attempt to parse string if decodedString is a byte slice of non-zero length
	if len(decodedString) > 0 {
		symbolString, err = parseStringReturn(artifacts.ERC20ABI, "symbol", decodedString)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to parse symbol: %s", ErrBadCurrency, err.Error())
		}
	}

	// If the parsed string is of zero length, default to defaultERC20Symbol
	if len(symbolString) == 0 {
		symbolString = defaultERC20Symbol
	}

	currency := &RosettaTypes.Currency{
		Symbol:   symbolString,
		Decimals: int32(decimalsBigInt.Int64()),
		Metadata: map[string]interface{}{
			ContractAddressKey: contractAddress,
		},
	}

	ecf.currencyCache.Add(contractAddress, currency)

	return currency, nil
}

func newERC20CurrencyFetcher(c JSONRPC) (CurrencyFetcher, error) {
	cache, err := lru.New(defaultCacheSize)
	if err != nil {
		return nil, err
	}

	return &ERC20CurrencyFetcher{cache, c}, nil
}
