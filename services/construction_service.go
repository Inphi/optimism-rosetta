// Copyright 2020 Coinbase, Inc.
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

package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/inphi/optimism-rosetta/configuration"
	"github.com/inphi/optimism-rosetta/optimism"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/coinbase/rosetta-sdk-go/parser"
	"github.com/coinbase/rosetta-sdk-go/types"
)

const (
	// TokenContractAddressKey is the key in the currency metadata map
	// that represents the contract address of a token
	TokenContractAddressKey = "token_address"
)

var (
	erc20TransferMethodID = crypto.Keccak256([]byte("transfer(address,uint256)"))[:4]
	delegateVotesMethodID = crypto.Keccak256([]byte("delegate(address)"))[:4]
)

// ConstructionAPIService implements the server.ConstructionAPIServicer interface.
type ConstructionAPIService struct {
	config *configuration.Configuration
	client Client
}

// NewConstructionAPIService creates a new instance of a ConstructionAPIService.
func NewConstructionAPIService(
	cfg *configuration.Configuration,
	client Client,
) *ConstructionAPIService {
	return &ConstructionAPIService{
		config: cfg,
		client: client,
	}
}

// ConstructionDerive implements the /construction/derive endpoint.
func (s *ConstructionAPIService) ConstructionDerive(
	ctx context.Context,
	request *types.ConstructionDeriveRequest,
) (*types.ConstructionDeriveResponse, *types.Error) {
	pubkey, err := crypto.DecompressPubkey(request.PublicKey.Bytes)
	if err != nil {
		return nil, wrapErr(ErrUnableToDecompressPubkey, err)
	}

	addr := crypto.PubkeyToAddress(*pubkey)
	return &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: addr.Hex(),
		},
	}, nil
}

// ConstructionPreprocess implements the /construction/preprocess
// endpoint.
func (s *ConstructionAPIService) ConstructionPreprocess(
	ctx context.Context,
	request *types.ConstructionPreprocessRequest,
) (*types.ConstructionPreprocessResponse, *types.Error) {
	fromOp, toOp, err := matchOperations(request.Operations)
	if err != nil {
		return nil, wrapErr(ErrUnclearIntent, err)
	}
	fromAdd := fromOp.Account.Address
	toAdd := toOp.Account.Address

	// Ensure valid from address
	checkFrom, ok := optimism.ChecksumAddress(fromAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", fromAdd))
	}

	// Ensure valid to address
	checkTo, ok := optimism.ChecksumAddress(toAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", toAdd))
	}

	value := new(big.Int)
	value.SetString(toOp.Amount.Value, 10)
	preprocessOutputOptions := &options{
		From:  checkFrom,
		To:    checkTo,
		Value: value,
	}

	// Override nonce
	if v, ok := request.Metadata["nonce"]; ok {
		stringObj, ok := v.(string)
		if !ok {
			return nil, wrapErr(
				ErrInvalidNonce,
				fmt.Errorf("%s is not a valid nonce string", v),
			)
		}
		bigObj, ok := new(big.Int).SetString(stringObj, 10) //nolint:gomnd
		if !ok {
			return nil, wrapErr(
				ErrInvalidNonce,
				fmt.Errorf("%s is not a valid nonce", v),
			)
		}
		preprocessOutputOptions.Nonce = bigObj
	}

	// Override gas_price
	if v, ok := request.Metadata["gas_price"]; ok {
		stringObj, ok := v.(string)
		if !ok {
			return nil, wrapErr(
				ErrInvalidGasPrice,
				fmt.Errorf("%s is not a valid gas_price string", v),
			)
		}
		bigObj, ok := new(big.Int).SetString(stringObj, 10) //nolint:gomnd
		if !ok {
			return nil, wrapErr(
				ErrInvalidGasPrice,
				fmt.Errorf("%s is not a valid gas_price", v),
			)
		}
		preprocessOutputOptions.GasPrice = bigObj
	}

	// Override gas_tip_cap
	if v, ok := request.Metadata["gas_tip_cap"]; ok {
		stringObj, ok := v.(string)
		if !ok {
			return nil, wrapErr(
				ErrInvalidGasTipCap,
				fmt.Errorf("%s is not a valid gas_tip_cap string", v),
			)
		}
		bigObj, ok := new(big.Int).SetString(stringObj, 10) //nolint:gomnd
		if !ok {
			return nil, wrapErr(
				ErrInvalidGasTipCap,
				fmt.Errorf("%s is not a valid gas_tip_cap", v),
			)
		}
		preprocessOutputOptions.GasTipCap = bigObj
	}

	// Override gas_fee_cap
	if v, ok := request.Metadata["gas_fee_cap"]; ok {
		stringObj, ok := v.(string)
		if !ok {
			return nil, wrapErr(
				ErrInvalidGasFeeCap,
				fmt.Errorf("%s is not a valid gas_fee_cap string", v),
			)
		}
		bigObj, ok := new(big.Int).SetString(stringObj, 10) //nolint:gomnd
		if !ok {
			return nil, wrapErr(
				ErrInvalidGasFeeCap,
				fmt.Errorf("%s is not a valid gas_fee_cap", v),
			)
		}
		preprocessOutputOptions.GasFeeCap = bigObj
	}

	// Override gas_limit
	if v, ok := request.Metadata["gas_limit"]; ok {
		stringObj, ok := v.(string)
		if !ok {
			return nil, wrapErr(
				ErrInvalidGasLimit,
				fmt.Errorf("expected gas_limit value to be string, instead got: %T", v),
			)
		}
		bigObj, ok := new(big.Int).SetString(stringObj, 10) //nolint:gomnd
		if !ok {
			return nil, wrapErr(
				ErrInvalidGasLimit,
				fmt.Errorf("%s is not a valid gas_limit", v),
			)
		}
		preprocessOutputOptions.GasLimit = bigObj
	}

	currency := fromOp.Amount.Currency
	opType := fromOp.Type
	if _, ok := request.Metadata["method_signature"]; !ok && !isNativeCurrency(currency) {
		tokenContractAddress, err := getTokenContractAddress(currency)
		if err != nil {
			return nil, wrapErr(ErrInvalidTokenContractAddress, err)
		}

		preprocessOutputOptions.TokenAddress = tokenContractAddress
		switch opType {
		case optimism.DelegateVotesOpType:
			preprocessOutputOptions.Data = constructERC20VotesDelegateData(checkTo)
			preprocessOutputOptions.Value = big.NewInt(0)
		default:
			preprocessOutputOptions.Data = constructERC20TransferData(checkTo, value)
			preprocessOutputOptions.Value = big.NewInt(0) // value is 0 when sending ERC20
		}
	}

	if v, ok := request.Metadata["method_signature"]; ok {
		methodSigStringObj := v.(string)
		if !ok {
			return nil, wrapErr(
				ErrInvalidSignature,
				fmt.Errorf("%s is not a valid signature string", v),
			)
		}
		data, err := constructContractCallData(methodSigStringObj, request.Metadata["method_args"])
		if err != nil {
			return nil, wrapErr(ErrFetchFunctionSignatureMethodID, err)
		}
		preprocessOutputOptions.ContractAddress = checkTo
		preprocessOutputOptions.Data = data
		preprocessOutputOptions.MethodSignature = methodSigStringObj
		preprocessOutputOptions.MethodArgs = request.Metadata["method_args"]
	}

	marshaled, err := marshalJSONMap(preprocessOutputOptions)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionPreprocessResponse{
		Options: marshaled,
	}, nil
}

// ConstructionMetadata implements the /construction/metadata endpoint.
func (s *ConstructionAPIService) ConstructionMetadata(
	ctx context.Context,
	request *types.ConstructionMetadataRequest,
) (*types.ConstructionMetadataResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, ErrUnavailableOffline
	}

	var input options
	if err := unmarshalJSONMap(request.Options, &input); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	if len(input.From) == 0 {
		return nil, wrapErr(ErrInvalidAddress, errors.New("source address is not provided"))
	}

	if len(input.To) == 0 {
		return nil, wrapErr(ErrInvalidAddress, errors.New("destination address is not provided"))
	}

	checkFrom, ok := optimism.ChecksumAddress(input.From)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", input.From))
	}

	checkTo, ok := optimism.ChecksumAddress(input.To)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", input.To))
	}

	nonce, err := s.calculateNonce(ctx, input.Nonce, checkFrom)
	if err != nil {
		return nil, wrapErr(ErrGeth, err)
	}

	var gasLimit uint64
	if input.GasLimit == nil {
		// by default, initialize gasLimit to the TransferGasLimit
		gasLimit = optimism.TransferGasLimit
	} else {
		if !input.GasLimit.IsUint64() {
			gasLimit = math.MaxUint64
		} else {
			gasLimit = input.GasLimit.Uint64()
		}
	}

	to := checkTo

	// For tokens only
	if len(input.TokenAddress) > 0 {
		checkTokenContractAddress, ok := optimism.ChecksumAddress(input.TokenAddress)
		if !ok {
			return nil, wrapErr(
				ErrInvalidAddress,
				fmt.Errorf("%s is not a valid address", input.TokenAddress),
			)
		}
		// Override the destination address to be the contract address
		to = checkTokenContractAddress

		if input.GasLimit == nil {
			var err *types.Error
			gasLimit, err = s.calculateGasLimit(ctx, checkFrom, checkTokenContractAddress, input.Data, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	// Only work for Generic Contract calls
	if len(input.ContractAddress) > 0 {
		checkContractAddress, ok := optimism.ChecksumAddress(input.ContractAddress)
		if !ok {
			return nil, wrapErr(
				ErrInvalidAddress,
				fmt.Errorf("%s is not a valid address", input.ContractAddress),
			)
		}
		// Override the destination address to be the contract address
		to = checkContractAddress

		if input.GasLimit == nil {
			var err *types.Error
			gasLimit, err = s.calculateGasLimit(ctx, checkFrom, checkContractAddress, input.Data, input.Value)
			if err != nil {
				return nil, err
			}
		}
	}

	// For backwards compatibility, the gasPrice is always provided in the response
	gasPrice, err := s.calculateGasPrice(ctx, input.GasPrice)
	if err != nil {
		return nil, wrapErr(ErrGeth, err)
	}
	gasTipCap, gasFeeCap, err := s.calculateFeeCaps(ctx, input.GasTipCap, input.GasFeeCap)
	if err != nil {
		return nil, wrapErr(ErrGeth, err)
	}

	metadata := &metadata{
		Nonce:           nonce,
		GasPrice:        gasPrice,
		GasTipCap:       gasTipCap,
		GasFeeCap:       gasFeeCap,
		GasLimit:        gasLimit,
		Data:            input.Data,
		Value:           input.Value,
		To:              to,
		MethodSignature: input.MethodSignature,
		MethodArgs:      input.MethodArgs,
	}

	metadataMap, err := marshalJSONMap(metadata)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	// Find suggested gas usage
	suggestedFee := metadata.GasPrice.Int64() * int64(gasLimit)
	if metadata.GasFeeCap != nil {
		suggestedFee = metadata.GasFeeCap.Int64() * int64(gasLimit)
	}

	return &types.ConstructionMetadataResponse{
		Metadata: metadataMap,
		SuggestedFee: []*types.Amount{
			{
				Value:    strconv.FormatInt(suggestedFee, 10),
				Currency: optimism.Currency,
			},
		},
	}, nil
}

// ConstructionPayloads implements the /construction/payloads endpoint.
func (s *ConstructionAPIService) ConstructionPayloads(
	ctx context.Context,
	request *types.ConstructionPayloadsRequest,
) (*types.ConstructionPayloadsResponse, *types.Error) {
	// Convert map to Metadata struct
	var metadata metadata
	if err := unmarshalJSONMap(request.Metadata, &metadata); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	fromOp, toOp, err := matchOperations(request.Operations)
	if err != nil {
		return nil, wrapErr(ErrUnclearIntent, err)
	}
	if err := validateRequest(fromOp, toOp, metadata); err != nil {
		return nil, wrapErr(ErrBadRequest, err)
	}

	fromAdd := fromOp.Account.Address
	amount := metadata.Value
	toAdd := metadata.To
	nonce := metadata.Nonce
	gasPrice := metadata.GasPrice
	gasTipCap := metadata.GasTipCap
	gasFeeCap := metadata.GasFeeCap
	chainID := s.config.Params.ChainID
	transferGasLimit := metadata.GasLimit
	transferData := metadata.Data

	// Ensure valid from address
	checkFrom, ok := optimism.ChecksumAddress(fromAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", fromAdd))
	}
	// Ensure valid to address
	checkTo, ok := optimism.ChecksumAddress(toAdd)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", toAdd))
	}

	unsignedTx := &transaction{
		From:      checkFrom,
		To:        checkTo,
		Value:     amount,
		Data:      transferData,
		Nonce:     nonce,
		GasPrice:  gasPrice,
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		GasLimit:  transferGasLimit,
		ChainID:   chainID,
	}
	signer := ethTypes.NewLondonSigner(chainID)
	sighash := signer.Hash(AsEthTransaction(unsignedTx))

	payload := &types.SigningPayload{
		AccountIdentifier: &types.AccountIdentifier{Address: checkFrom},
		Bytes:             sighash.Bytes(),
		SignatureType:     types.EcdsaRecovery,
	}

	unsignedTxJSON, err := json.Marshal(unsignedTx)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionPayloadsResponse{
		UnsignedTransaction: string(unsignedTxJSON),
		Payloads:            []*types.SigningPayload{payload},
	}, nil
}

// ConstructionCombine implements the /construction/combine
// endpoint.
func (s *ConstructionAPIService) ConstructionCombine(
	ctx context.Context,
	request *types.ConstructionCombineRequest,
) (*types.ConstructionCombineResponse, *types.Error) {
	if len(request.UnsignedTransaction) == 0 {
		return nil, wrapErr(ErrInvalidTransaction, errors.New("transaction data is not provided"))
	}
	if len(request.Signatures) == 0 {
		return nil, wrapErr(ErrInvalidSignature, errors.New("signature is not provided"))
	}

	var unsignedTx transaction
	if err := json.Unmarshal([]byte(request.UnsignedTransaction), &unsignedTx); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	ethTransaction := AsEthTransaction(&unsignedTx)
	signer := ethTypes.NewLondonSigner(unsignedTx.ChainID)
	signedTx, err := ethTransaction.WithSignature(signer, request.Signatures[0].Bytes)
	if err != nil {
		return nil, wrapErr(ErrSignatureInvalid, err)
	}

	signedTxJSON, err := signedTx.MarshalJSON()
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	return &types.ConstructionCombineResponse{
		SignedTransaction: string(signedTxJSON),
	}, nil
}

// ConstructionHash implements the /construction/hash endpoint.
func (s *ConstructionAPIService) ConstructionHash(
	ctx context.Context,
	request *types.ConstructionHashRequest,
) (*types.TransactionIdentifierResponse, *types.Error) {
	signedTx := ethTypes.Transaction{}
	if err := signedTx.UnmarshalJSON([]byte(request.SignedTransaction)); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	hash := signedTx.Hash().Hex()

	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: &types.TransactionIdentifier{
			Hash: hash,
		},
	}, nil
}

// ConstructionParse implements the /construction/parse endpoint.
func (s *ConstructionAPIService) ConstructionParse(
	ctx context.Context,
	request *types.ConstructionParseRequest,
) (*types.ConstructionParseResponse, *types.Error) {
	var tx transaction
	if !request.Signed {
		err := json.Unmarshal([]byte(request.Transaction), &tx)
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}
	} else {
		t := new(ethTypes.Transaction)
		err := t.UnmarshalJSON([]byte(request.Transaction))
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}

		tx.To = t.To().String()
		tx.Value = t.Value()
		tx.Data = t.Data()
		tx.Nonce = t.Nonce()
		tx.GasPrice = t.GasPrice()
		tx.GasFeeCap = t.GasFeeCap()
		tx.GasTipCap = t.GasTipCap()
		tx.GasLimit = t.Gas()
		tx.ChainID = t.ChainId()

		msg, err := t.AsMessage(ethTypes.NewLondonSigner(t.ChainId()), nil)
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}

		tx.From = msg.From().Hex()
	}

	currency := optimism.Currency
	opType := optimism.CallOpType

	//TODO: add logic for contract call parsing ERC20 currency
	if hasData(tx.Data) && dataHasFunc(tx.Data, erc20TransferMethodID) {
		toAdd, amount, err := erc20TransferArgs(tx.Data)
		if err != nil {
			return nil, wrapErr(ErrUnableToParseTransaction, err)
		}

		// TODO(inphi): We assume that the token here is the OP token since that's the only supported one. But we should autodetect the appropriate token here
		currency = &types.Currency{
			Symbol:   "OP",
			Decimals: 18, //nolint
			Metadata: map[string]interface{}{
				TokenContractAddressKey: tx.To,
			},
		}
		// Update destination address to be the actual recipient
		tx.To = toAdd.String()
		tx.Value = amount
		opType = optimism.PaymentOpType
	} else if hasData(tx.Data) && dataHasFunc(tx.Data, delegateVotesMethodID) {
		delegatee, err := erc20VotesDelegateArgs(tx.Data)
		if err != nil {
			return nil, wrapErr(ErrUnableToParseTransaction, err)
		}

		// TODO(inphi): We assume that the token here is the OP token since that's the only supported one. But we should autodetect the appropriate token here
		currency = &types.Currency{
			Symbol:   "OP",
			Decimals: 18, //nolint
			Metadata: map[string]interface{}{
				TokenContractAddressKey: tx.To,
			},
		}
		// Update destination address to be the actual recipient
		tx.To = delegatee.String()
		opType = optimism.DelegateVotesOpType
	}

	// Ensure valid from address
	checkFrom, ok := optimism.ChecksumAddress(tx.From)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", tx.From))
	}

	// Ensure valid to address
	checkTo, ok := optimism.ChecksumAddress(tx.To)
	if !ok {
		return nil, wrapErr(ErrInvalidAddress, fmt.Errorf("%s is not a valid address", tx.To))
	}

	ops := rosettaOperations(checkFrom, checkTo, tx.Value, currency, opType)

	metadata := &parseMetadata{
		Nonce:     tx.Nonce,
		GasPrice:  tx.GasPrice,
		GasTipCap: tx.GasTipCap,
		GasFeeCap: tx.GasFeeCap,
		GasLimit:  tx.GasLimit,
		ChainID:   tx.ChainID,
	}
	metaMap, err := marshalJSONMap(metadata)
	if err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	var resp *types.ConstructionParseResponse
	if request.Signed {
		resp = &types.ConstructionParseResponse{
			Operations: ops,
			AccountIdentifierSigners: []*types.AccountIdentifier{
				{
					Address: checkFrom,
				},
			},
			Metadata: metaMap,
		}
	} else {
		resp = &types.ConstructionParseResponse{
			Operations:               ops,
			AccountIdentifierSigners: []*types.AccountIdentifier{},
			Metadata:                 metaMap,
		}
	}
	return resp, nil
}

// ConstructionSubmit implements the /construction/submit endpoint.
func (s *ConstructionAPIService) ConstructionSubmit(
	ctx context.Context,
	request *types.ConstructionSubmitRequest,
) (*types.TransactionIdentifierResponse, *types.Error) {
	if s.config.Mode != configuration.Online {
		return nil, ErrUnavailableOffline
	}

	if len(request.SignedTransaction) == 0 {
		return nil, wrapErr(ErrInvalidTransaction, errors.New("signed transaction value is not provided"))
	}

	var signedTx ethTypes.Transaction
	if err := signedTx.UnmarshalJSON([]byte(request.SignedTransaction)); err != nil {
		return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
	}

	if err := s.client.SendTransaction(ctx, &signedTx); err != nil {
		return nil, wrapErr(ErrBroadcastFailed, err)
	}

	txIdentifier := &types.TransactionIdentifier{
		Hash: signedTx.Hash().Hex(),
	}
	return &types.TransactionIdentifierResponse{
		TransactionIdentifier: txIdentifier,
	}, nil
}

// calculatesGasLimit calculates the gasLimit for an ERC20 transfer
// if gas limit is not provided
func (s *ConstructionAPIService) calculateGasLimit(
	ctx context.Context,
	from string,
	to string,
	data []byte,
	value *big.Int,
) (uint64, *types.Error) {
	fromAddress := common.HexToAddress(from)
	toAddress := common.HexToAddress(to)
	var v *big.Int
	if value != nil && value.Cmp(big.NewInt(0)) != 0 {
		v = value
	}
	gasLimit, err := s.client.EstimateGas(ctx, ethereum.CallMsg{
		From:  fromAddress,
		To:    &toAddress,
		Data:  data,
		Value: v,
	})

	if err != nil {
		return 0, wrapErr(ErrGeth, err)
	}

	return gasLimit, nil
}

// calculateNonce will calculate the nonce for the from address if
// nonce is not provided
func (s *ConstructionAPIService) calculateNonce(
	ctx context.Context,
	nonceInput *big.Int,
	from string,
) (uint64, error) {
	if nonceInput == nil {
		nonce, err := s.client.PendingNonceAt(ctx, common.HexToAddress(from))
		if err != nil {
			return 0, err
		}
		return nonce, nil
	}
	return nonceInput.Uint64(), nil
}

// calculateGasPrice returns a suggested gas price if gas price is not provided
func (s *ConstructionAPIService) calculateGasPrice(
	ctx context.Context,
	gasPriceInput *big.Int,
) (*big.Int, error) {
	if gasPriceInput == nil {
		return s.client.SuggestGasPrice(ctx)
	}
	return gasPriceInput, nil
}

// calculateGasFeeCaps returns suggested gas tip and fee caps if gas tip and fee caps are not provided
func (s *ConstructionAPIService) calculateFeeCaps(ctx context.Context, gasTipCapInput *big.Int, gasFeeCapInput *big.Int) (
	gasTipCap *big.Int,
	gasFeeCap *big.Int,
	err error,
) {
	if gasTipCapInput == nil || gasFeeCapInput == nil {
		baseFee, err := s.client.BaseFee(ctx)
		if err != nil {
			return nil, nil, err
		}
		// If baseFee is not nil, then add EIP-1559 fee parameters to metadata
		if baseFee != nil {
			gasTipCap, err := s.client.SuggestGasTipCap(ctx)
			if err != nil {
				return nil, nil, err
			}
			// TODO(inphi): Priority fee estimation doesn't quite work yet and may return an overestimate so we don't use it for now.
			// Furthermore, Rosetta currently retrieves fee estimates from an op-geth instance that syncs from L1. On average, the safe
			// chain is behind the unsafe chain by 50 blocks. This means the base fee is 50 blocks old and may be inaccurate.
			// Based on a recent analysis on base fee changes on Optimism Mainnet, it was found that the 99th percentile error in base fees
			// between the safe and unsafe chain shows an increase of approximately 76%. For extra safety, we set the gas price to be twice the base
			// fee to ensure transaction inclusion. Ideally, Rosetta should lookup base fee info from the unsafe chain for more accurate gas pricing.
			// Although inefficient, the SuggestGasTipCap RPC call still occurs so tests can mock it properly
			gasTipCap = new(big.Int).Set(baseFee)
			gasFeeCap := new(big.Int).Add(baseFee, gasTipCap)
			return gasTipCap, gasFeeCap, nil
		}
	}

	return gasTipCapInput, gasFeeCapInput, nil
}

// matchOperations attempts to match a slice of operations with both `transfer`
// and `delegate` intents. This will match ETH, ERC20 and OZ ERC20Votes tokens
func matchOperations(operations []*types.Operation) (
	*types.Operation,
	*types.Operation,
	error,
) {
	operationDescriptions, err := matchOperationDescriptions(operations)
	if err != nil {
		return nil, nil, err
	}

	descriptions := &parser.Descriptions{
		OperationDescriptions: operationDescriptions,
		ErrUnmatched:          true,
	}

	matches, err := parser.MatchOperations(descriptions, operations)
	if err != nil {
		return nil, nil, err
	}

	fromOp, _ := matches[0].First()
	toOp, _ := matches[1].First()
	return fromOp, toOp, nil
}

func matchOperationDescriptions(operations []*types.Operation) ([]*parser.OperationDescription, error) {
	if len(operations) != 2 {
		return nil, fmt.Errorf("invalid number of operations")
	}

	firstCurrency := operations[0].Amount.Currency
	secondCurrency := operations[1].Amount.Currency
	if firstCurrency == nil || secondCurrency == nil {
		return nil, fmt.Errorf("invalid currency on operation")
	}
	if !reflect.DeepEqual(firstCurrency, secondCurrency) {
		return nil, fmt.Errorf("from and to currencies are not equal")
	}

	opType := optimism.CallOpType
	if !isNativeCurrency(firstCurrency) {
		_, firstOk := firstCurrency.Metadata[TokenContractAddressKey].(string)
		_, secondOk := secondCurrency.Metadata[TokenContractAddressKey].(string)
		if !firstOk || !secondOk {
			return nil, fmt.Errorf("non-native currency must have token_address in metadata")
		}
		opType = operations[0].Type
		if opType == "" { // default to PaymentOpType for backwards compatibility
			opType = optimism.PaymentOpType
		}
	}

	return []*parser.OperationDescription{
		{
			Type: opType,
			Account: &parser.AccountDescription{
				Exists: true,
			},
			Amount: &parser.AmountDescription{
				Exists:   true,
				Sign:     parser.NegativeOrZeroAmountSign,
				Currency: firstCurrency,
			},
		},
		{
			Type: opType,
			Account: &parser.AccountDescription{
				Exists: true,
			},
			Amount: &parser.AmountDescription{
				Exists:   true,
				Sign:     parser.PositiveOrZeroAmountSign,
				Currency: firstCurrency,
			},
		},
	}, nil
}

// isNativeCurrency checks if the currency is the native currency
func isNativeCurrency(currency *types.Currency) bool {
	if currency == nil {
		return false
	}
	return reflect.DeepEqual(currency, optimism.Currency)
}

// getTokenContractAddress retrieves and validates the contract address
func getTokenContractAddress(currency *types.Currency) (string, error) {
	v, exists := currency.Metadata[TokenContractAddressKey]
	if !exists {
		return "", errors.New("missing token contract address")
	}

	tokenContractAddress, ok := v.(string)
	if !ok {
		return "", errors.New("token contract address is not a string")
	}

	checkTokenContractAddress, ok := optimism.ChecksumAddress(tokenContractAddress)
	if !ok {
		return "", errors.New("token contract address is not a valid address")
	}

	// TODO: verify token contract address actually exist and the Symbol matches
	return checkTokenContractAddress, nil
}

// constructERC20TransferData constructs the data field of an Optimism
// transaction, including the recipient address and the amount
func constructERC20TransferData(to string, value *big.Int) []byte {
	methodID := erc20TransferMethodID

	var data []byte
	data = append(data, methodID...)

	toAddress := common.HexToAddress(to)
	paddedToAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	data = append(data, paddedToAddress...)

	paddedAmount := common.LeftPadBytes(value.Bytes(), 32)
	data = append(data, paddedAmount...)

	return data
}

// constructERC20VotesDelegateData constructs thee data field of a
// ERC20Votes delegate call
func constructERC20VotesDelegateData(to string) []byte {
	var data []byte

	methodID := crypto.Keccak256([]byte("delegate(address)"))[:4]
	data = append(data, methodID...)

	toAddress := common.HexToAddress(to)
	paddedToAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	data = append(data, paddedToAddress...)

	return data
}

// constructContractCallData constructs the data field of an Optimism transaction
func constructContractCallData(methodSig string, methodArgsGeneric interface{}) ([]byte, error) {
	data := contractCallMethodID(methodSig)

	// switch on the type of the method args. method args can come in from json as either a string or list of strings
	switch methodArgs := methodArgsGeneric.(type) {
	// case 0: no method arguments, return the selector
	case nil:
		return data, nil

	// case 1: method args are pre-compiled ABI data. decode the hex and create the call data directly
	case string:
		methodArgs = strings.TrimPrefix(methodArgs, "0x")
		b, decErr := hex.DecodeString(methodArgs)
		if decErr != nil {
			return nil, fmt.Errorf("error decoding method args hex data: %w", decErr)
		}
		return append(data, b...), nil

	// case 2: method args are a list of interface{} which will be converted to string before encoding
	case []interface{}:
		var strList []string
		for i, genericVal := range methodArgs {
			strVal, isStrVal := genericVal.(string)
			if !isStrVal {
				return nil, fmt.Errorf("invalid method_args type at index %d: %T (must be a string)",
					i, genericVal,
				)
			}
			strList = append(strList, strVal)
		}
		return encodeMethodArgsStrings(data, methodSig, strList)

	// case 3: method args are encoded as a list of strings, which will be decoded
	case []string:
		return encodeMethodArgsStrings(data, methodSig, methodArgs)

	// case 4: there is no known way to decode the method args
	default:
		return nil, fmt.Errorf(
			"invalid method_args type, accepted values are []string and hex-encoded string."+
				" type received=%T value=%#v", methodArgsGeneric, methodArgsGeneric,
		)
	}
}

func encodeMethodArgsStrings(sigData []byte, methodSig string, methodArgs []string) ([]byte, error) {
	var arguments abi.Arguments
	var argumentsData []interface{}

	splitSigByLeadingParenthesis := strings.Split(methodSig, "(")
	if len(splitSigByLeadingParenthesis) < 2 {
		return nil, nil
	}
	splitSigByTrailingParenthesis := strings.Split(splitSigByLeadingParenthesis[1], ")")
	if len(splitSigByTrailingParenthesis) < 1 {
		return nil, nil
	}
	splitSigByComma := strings.Split(splitSigByTrailingParenthesis[0], ",")

	if len(splitSigByComma) != len(methodArgs) {
		return nil, errors.New("invalid method arguments")
	}

	for i, v := range splitSigByComma {
		typed, _ := abi.NewType(v, v, nil)
		argument := abi.Arguments{
			{
				Type: typed,
			},
		}

		arguments = append(arguments, argument...)
		var argData interface{}

		switch {
		case v == "address":
			{
				argData = common.HexToAddress(methodArgs[i])
			}
		case v == "uint32":
			{
				u64, err := strconv.ParseUint(methodArgs[i], 10, 32)
				if err != nil {
					return nil, err
				}
				argData = uint32(u64)
			}
		case strings.HasPrefix(v, "uint") || strings.HasPrefix(v, "int"):
			{
				value := new(big.Int)
				value.SetString(methodArgs[i], 10)
				argData = value
			}
		case strings.HasPrefix(v, "bytes"):
			{
				var value []byte
				copy(value, methodArgs[i])
				argData = value
			}
		case strings.HasPrefix(v, "string"):
			{
				argData = methodArgs[i]
			}
		case strings.HasPrefix(v, "bool"):
			{
				value, err := strconv.ParseBool(methodArgs[i])
				if err != nil {
					log.Fatal(err)
				}
				argData = value
			}
		}
		argumentsData = append(argumentsData, argData)
	}
	encData, packErr := arguments.PackValues(argumentsData)
	return append(sigData, encData...), packErr
}

// validateRequest validates if the intent in operations matches
// the intent in metadata of this particular request
//
//nolint:unparam,gocritic
func validateRequest(
	fromOp *types.Operation,
	toOp *types.Operation,
	metadata metadata,
) error {
	if !hasData(metadata.Data) {
		// Native currency
		// Validate destination address
		if !strings.EqualFold(metadata.To, toOp.Account.Address) {
			return errors.New("mismatch destination address")
		}
		// Validate transfer value
		if metadata.Value.String() != toOp.Amount.Value {
			return errors.New("mismatch transfer value")
		}
	} else if dataHasFunc(metadata.Data, erc20TransferMethodID) {
		// ERC20
		toAdd, amount, err := erc20TransferArgs(metadata.Data)
		if err != nil {
			return err
		}
		// Validate destination address
		if toAdd != common.HexToAddress(toOp.Account.Address) {
			return errors.New("mismatch destination address")
		}
		// Validate transfer value
		if amount.String() != toOp.Amount.Value {
			return errors.New("mismatch transfer value")
		}
		// Validate metadata value
		if metadata.Value.String() != "0" {
			return errors.New("invalid metadata value")
		}
	} else if dataHasFunc(metadata.Data, delegateVotesMethodID) {
		// OZ ERC20Votes delegate call
		delegatee, err := erc20VotesDelegateArgs(metadata.Data)
		if err != nil {
			return err
		}
		if delegatee != common.HexToAddress(toOp.Account.Address) {
			return errors.New("mismatch delegatee destination address")
		}
		if toOp.Amount.Value != "0" {
			return errors.New("invalid delegatee transfer value")
		}
		if metadata.Value.String() != "0" {
			return errors.New("invalid metadata value for delegation")
		}
	} else {
		// other contract calls
		data, err := constructContractCallData(metadata.MethodSignature, metadata.MethodArgs)
		if err != nil {
			return err
		}
		res := bytes.Compare(data, metadata.Data)
		if res != 0 {
			return errors.New("invalid data value")
		}
	}

	return nil
}

// hasData determines if the data or input on a transfer
// transaction is empty or not.
func hasData(data []byte) bool {
	return len(data) > 0
}

// erc20TransferArgs returns the arguments for an ERC20 transfer,
// including destination address and value
func erc20TransferArgs(data []byte) (common.Address, *big.Int, error) {
	if data == nil || len(data) != 4+32+32 {
		return common.Address{}, nil, errors.New("invalid transfer data")
	}
	methodID := data[:4]
	toAdd := common.BytesToAddress(data[4:36])
	amount := big.NewInt(0).SetBytes(data[36:])

	expectedMethodID := erc20TransferMethodID
	if res := bytes.Compare(methodID, expectedMethodID); res != 0 {
		return common.Address{}, nil, errors.New("invalid transfer method id")
	}

	return toAdd, amount, nil
}

func erc20VotesDelegateArgs(data []byte) (common.Address, error) {
	if data == nil || len(data) != 4+32 {
		return common.Address{}, errors.New("invalid delegate data")
	}
	if !dataHasFunc(data, delegateVotesMethodID) {
		return common.Address{}, errors.New("invalid delegate method id")
	}
	delegatee := common.BytesToAddress(data[4:36])
	return delegatee, nil
}

func dataHasFunc(data []byte, expectedMethodID []byte) bool {
	methodID := data[:4]
	return bytes.Equal(methodID, expectedMethodID)
}

func rosettaOperations(
	fromAddress string,
	toAddress string,
	amount *big.Int,
	currency *types.Currency,
	opType string,
) []*types.Operation {
	return []*types.Operation{
		{
			OperationIdentifier: &types.OperationIdentifier{
				Index: 0,
			},
			Type: opType,
			Account: &types.AccountIdentifier{
				Address: fromAddress,
			},
			Amount: &types.Amount{
				Value:    new(big.Int).Neg(amount).String(),
				Currency: currency,
			},
		},
		{
			OperationIdentifier: &types.OperationIdentifier{
				Index: 1,
			},
			RelatedOperations: []*types.OperationIdentifier{
				{
					Index: 0,
				},
			},
			Type: opType,
			Account: &types.AccountIdentifier{
				Address: toAddress,
			},
			Amount: &types.Amount{
				Value:    amount.String(),
				Currency: currency,
			},
		},
	}
}

// contractCallMethodID calculates the first 4 bytes of the method
// signature for function call on contract
func contractCallMethodID(methodSig string) []byte {
	fnSignature := []byte(methodSig)
	hash := crypto.Keccak256(fnSignature)
	return hash[:4]
}
