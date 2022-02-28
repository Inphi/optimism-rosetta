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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/coinbase/rosetta-ethereum/configuration"
	"github.com/coinbase/rosetta-ethereum/optimism"
	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	"github.com/ethereum-optimism/optimism/l2geth/accounts/abi"
	"github.com/ethereum-optimism/optimism/l2geth/common"

	ethTypes "github.com/ethereum-optimism/optimism/l2geth/core/types"
	"github.com/ethereum-optimism/optimism/l2geth/crypto"

	"github.com/coinbase/rosetta-sdk-go/parser"
	"github.com/coinbase/rosetta-sdk-go/types"
)

const (
	// TokenContractAddressKey is the key in the currency metadata map
	// that represents the contract address of a token
	TokenContractAddressKey = "token_address"
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
	isContractCall := false
	if _, ok := request.Metadata["method_signature"]; ok {
		isContractCall = true
	}

	fromOp, toOp, err := matchTransferOperations(request.Operations, isContractCall)
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

	currency := fromOp.Amount.Currency
	if _, ok := request.Metadata["method_signature"]; !ok && !isNativeCurrency(currency) {
		tokenContractAddress, err := getTokenContractAddress(currency)
		if err != nil {
			return nil, wrapErr(ErrInvalidTokenContractAddress, err)
		}

		preprocessOutputOptions.TokenAddress = tokenContractAddress
		preprocessOutputOptions.Data = constructERC20TransferData(checkTo, value)
		preprocessOutputOptions.Value = big.NewInt(0) // value is 0 when sending ERC20
	}

	if v, ok := request.Metadata["method_signature"]; ok {
		methodSigStringObj := v.(string)
		if !ok {
			return nil, wrapErr(
				ErrInvalidSignature,
				fmt.Errorf("%s is not a valid signature string", v),
			)
		}
		var methodArgs []string
		if v, ok := request.Metadata["method_args"]; ok {
			methodArgsBytes, _ := json.Marshal(v)
			err := json.Unmarshal(methodArgsBytes, &methodArgs)
			if err != nil {
				fmt.Println("Error in unmarshal")
			}
		}
		data, err := constructContractCallData(methodSigStringObj, methodArgs)
		if err != nil {
			return nil, wrapErr(ErrFetchFunctionSignatureMethodID, err)
		}
		preprocessOutputOptions.ContractAddress = checkTo
		preprocessOutputOptions.Data = data
		preprocessOutputOptions.MethodSignature = methodSigStringObj
		preprocessOutputOptions.MethodArgs = methodArgs
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

	gasLimit := optimism.TransferGasLimit
	to := checkTo

	// Only work for ERC20 transfer
	if len(input.TokenAddress) > 0 {
		checkTokenContractAddress, ok := optimism.ChecksumAddress(input.TokenAddress)
		if !ok {
			return nil, wrapErr(
				ErrInvalidAddress,
				fmt.Errorf("%s is not a valid address", input.TokenAddress),
			)
		}
		// TODO(inphi): Whitelist ERC20 contracts for token transfers here

		// Override the destination address to be the contract address
		to = checkTokenContractAddress

		var err *types.Error
		gasLimit, err = s.calculateGasLimit(ctx, checkFrom, checkTokenContractAddress, input.Data, nil)
		if err != nil {
			return nil, err
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

		var err *types.Error
		gasLimit, err = s.calculateGasLimit(ctx, checkFrom, checkContractAddress, input.Data, input.Value)
		if err != nil {
			return nil, err
		}
	}

	// TODO(inphi): Upgrade to use EIP1559 on mainnet once avaialble
	gasPrice, err := s.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, wrapErr(ErrGeth, err)
	}

	metadata := &metadata{
		Nonce:           nonce,
		GasPrice:        gasPrice,
		GasLimit:        big.NewInt(int64(gasLimit)),
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
	isContractCall := false
	if hasData(metadata.Data) && !hasTransferData(metadata.Data) {
		isContractCall = true
	}

	fromOp, toOp, err := matchTransferOperations(request.Operations, isContractCall)
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
	chainID := s.config.Params.ChainID
	transferGasLimit := metadata.GasLimit.Uint64()
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

	tx := ethTypes.NewTransaction(
		nonce,
		common.HexToAddress(checkTo),
		amount,
		transferGasLimit,
		gasPrice,
		transferData,
	)

	unsignedTx := &transaction{
		From:     checkFrom,
		To:       checkTo,
		Value:    amount,
		Data:     tx.Data(),
		Nonce:    tx.Nonce(),
		GasPrice: gasPrice,
		GasLimit: tx.Gas(),
		ChainID:  chainID,
	}

	// Construct SigningPayload
	signer := ethTypes.NewEIP155Signer(chainID)
	payload := &types.SigningPayload{
		AccountIdentifier: &types.AccountIdentifier{Address: checkFrom},
		Bytes:             signer.Hash(tx).Bytes(),
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

	ethTransaction := ethTypes.NewTransaction(
		unsignedTx.Nonce,
		common.HexToAddress(unsignedTx.To),
		unsignedTx.Value,
		unsignedTx.GasLimit,
		unsignedTx.GasPrice,
		unsignedTx.Data,
	)

	signer := ethTypes.NewEIP155Signer(unsignedTx.ChainID)
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
		tx.GasLimit = t.Gas()
		tx.ChainID = t.ChainId()

		msg, err := t.AsMessage(ethTypes.NewEIP155Signer(t.ChainId()))
		if err != nil {
			return nil, wrapErr(ErrUnableToParseIntermediateResult, err)
		}

		tx.From = msg.From().Hex()
	}

	currency := optimism.Currency

	//TODO: add logic for contract call parsing ERC20 currency
	if hasData(tx.Data) && hasTransferData(tx.Data) {
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
		tx.To = toAdd
		tx.Value = amount
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

	ops := rosettaOperations(checkFrom, checkTo, tx.Value, currency)

	metadata := &parseMetadata{
		Nonce:    tx.Nonce,
		GasPrice: tx.GasPrice,
		GasLimit: tx.GasLimit,
		ChainID:  tx.ChainID,
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
func (a *ConstructionAPIService) calculateNonce(
	ctx context.Context,
	nonceInput *big.Int,
	from string,
) (uint64, error) {
	if nonceInput == nil {
		nonce, err := a.client.PendingNonceAt(ctx, common.HexToAddress(from))
		if err != nil {
			return 0, err
		}
		return nonce, nil
	}
	return nonceInput.Uint64(), nil
}

// matchTransferOperations attempts to match a slice of operations with a `transfer`
// intent. This will match both ETH and ERC20 tokens
func matchTransferOperations(operations []*types.Operation, isContractCall bool) (
	*types.Operation,
	*types.Operation,
	error,
) {
	valueOne, err := strconv.ParseInt(operations[0].Amount.Value, 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	valueTwo, err := strconv.ParseInt(operations[1].Amount.Value, 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	if isContractCall && valueOne == 0 {
		if valueOne != valueTwo {
			return nil, nil, errors.New("for generic call both values should be zero")
		}
		descriptions := &parser.Descriptions{
			OperationDescriptions: []*parser.OperationDescription{
				{
					Type: optimism.CallOpType,
					Account: &parser.AccountDescription{
						Exists: true,
					},
					Amount: &parser.AmountDescription{
						Exists: true,
						Sign:   parser.AnyAmountSign,
					},
				},
				{
					Type: optimism.CallOpType,
					Account: &parser.AccountDescription{
						Exists: true,
					},
					Amount: &parser.AmountDescription{
						Exists: true,
						Sign:   parser.AnyAmountSign,
					},
				},
			},
			ErrUnmatched: true,
		}

		matches, err := parser.MatchOperations(descriptions, operations)
		if err != nil {
			return nil, nil, err
		}

		fromOp, _ := matches[0].First()
		toOp, _ := matches[1].First()

		// Manually validate currencies since we cannot rely on parser
		if fromOp.Amount.Currency == nil || toOp.Amount.Currency == nil {
			return nil, nil, errors.New("missing currency")
		}

		if !reflect.DeepEqual(fromOp.Amount.Currency, toOp.Amount.Currency) {
			return nil, nil, errors.New("from and to currencies are not equal")
		}

		return fromOp, toOp, nil

	}
	descriptions := &parser.Descriptions{
		OperationDescriptions: []*parser.OperationDescription{
			{
				Type: optimism.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists: true,
					Sign:   parser.NegativeAmountSign,
				},
			},
			{
				Type: optimism.CallOpType,
				Account: &parser.AccountDescription{
					Exists: true,
				},
				Amount: &parser.AmountDescription{
					Exists: true,
					Sign:   parser.PositiveAmountSign,
				},
			},
		},
		ErrUnmatched: true,
	}

	matches, err := parser.MatchOperations(descriptions, operations)
	if err != nil {
		return nil, nil, err
	}

	fromOp, _ := matches[0].First()
	toOp, _ := matches[1].First()

	// Manually validate currencies since we cannot rely on parser
	if fromOp.Amount.Currency == nil || toOp.Amount.Currency == nil {
		return nil, nil, errors.New("missing currency")
	}

	if !reflect.DeepEqual(fromOp.Amount.Currency, toOp.Amount.Currency) {
		return nil, nil, errors.New("from and to currencies are not equal")
	}

	return fromOp, toOp, nil
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
	methodID := erc20TransferMethodID()

	var data []byte
	data = append(data, methodID...)

	toAddress := common.HexToAddress(to)
	paddedToAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
	data = append(data, paddedToAddress...)

	paddedAmount := common.LeftPadBytes(value.Bytes(), 32)
	data = append(data, paddedAmount...)

	return data
}

// erc20TransferMethodID calculates the first 4 bytes of the method
// signature for transfer on an ERC20 contract
func erc20TransferMethodID() []byte {
	transferFnSignature := []byte("transfer(address,uint256)")
	hash := crypto.Keccak256(transferFnSignature)
	return hash[:4]
}

// constructContractCallData constructs the data field of an Optimism transaction
func constructContractCallData(methodSig string, methodArgs []string) ([]byte, error) {
	arguments := abi.Arguments{}
	argumentsData := []interface{}{}

	var data []byte
	methodID := contractCallMethodID(methodSig)
	data = append(data, methodID...)

	splitSigByLeadingParenthesis := strings.Split(methodSig, "(")
	if len(splitSigByLeadingParenthesis) < 2 {
		return data, nil
	}
	splitSigByTrailingParenthesis := strings.Split(splitSigByLeadingParenthesis[1], ")")
	if len(splitSigByTrailingParenthesis) < 1 {
		return data, nil
	}
	splitSigByComma := strings.Split(splitSigByTrailingParenthesis[0], ",")

	if len(splitSigByComma) != len(methodArgs) {
		return nil, errors.New("Invalid method arguments")
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
		case strings.HasPrefix(v, "uint") || strings.HasPrefix(v, "int"):
			{
				value := new(big.Int)
				value.SetString(methodArgs[i], 10)
				argData = value
			}
		case strings.HasPrefix(v, "bytes"):
			{
				value := [32]byte{}
				copy(value[:], []byte(methodArgs[i]))
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
	abiEncodeData, _ := arguments.PackValues(argumentsData)
	data = append(data, abiEncodeData...)
	return data, nil
}

// validateRequest validates if the intent in operations matches
// the intent in metadata of this particular request
func validateRequest(
	fromOp *types.Operation,
	toOp *types.Operation,
	metadata metadata,
) error {
	if !hasData(metadata.Data) {
		// Native currency
		// Validate destination address
		if metadata.To != toOp.Account.Address {
			return errors.New("mismatch destination address")
		}
		// Validate transfer value
		if metadata.Value.String() != toOp.Amount.Value {
			return errors.New("mismatch transfer value")
		}
	} else if hasTransferData(metadata.Data) {
		// ERC20
		toAdd, amount, err := erc20TransferArgs(metadata.Data)
		if err != nil {
			return err
		}
		// Validate destination address
		if toAdd != toOp.Account.Address {
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
	} else if hasData(metadata.Data) && !hasTransferData(metadata.Data) {

		//contract call
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
func erc20TransferArgs(data []byte) (string, *big.Int, error) {
	if data == nil || len(data) != 4+32+32 {
		return "", nil, errors.New("invalid data")
	}
	methodID := data[:4]
	toAdd := common.BytesToAddress(data[4:36]).String()
	amount := big.NewInt(0).SetBytes(data[36:])

	expectedMethodID := erc20TransferMethodID()
	if res := bytes.Compare(methodID, expectedMethodID); res != 0 {
		return "", nil, errors.New("invalid method id")
	}

	return toAdd, amount, nil
}

func hasTransferData(data []byte) bool {
	methodID := data[:4]
	expectedMethodID := erc20TransferMethodID()
	res := bytes.Compare(methodID, expectedMethodID)
	if res != 0 {
		return false
	}
	return true
}

func rosettaOperations(
	fromAddress string,
	toAddress string,
	amount *big.Int,
	currency *types.Currency,
) []*types.Operation {
	return []*types.Operation{
		{
			OperationIdentifier: &types.OperationIdentifier{
				Index: 0,
			},
			Type: optimism.CallOpType,
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
			Type: optimism.CallOpType,
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
