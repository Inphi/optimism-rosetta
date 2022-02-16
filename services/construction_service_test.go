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
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/coinbase/rosetta-ethereum/configuration"
	mocks "github.com/coinbase/rosetta-ethereum/mocks/services"
	"github.com/coinbase/rosetta-ethereum/optimism"

	"github.com/coinbase/rosetta-sdk-go/types"
	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	fromAddress          = "0x966fbC4E1F3a938Cf7798695C3244d9C7C190015"
	toAddress            = "0xefD3dc58D60aF3295B92ecd484CAEB3A2f30b3e7"
	tokenContractAddress = "0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e"

	transferValue         = uint64(20211004)
	transferGasPrice      = uint64(5000000000)
	transferGasLimit      = uint64(21000)
	transferGasLimitERC20 = uint64(65000)
	transferNonce         = uint64(67)
	transferData          = "0xa9059cbb000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c" //nolint

	transferValueHex         = hexutil.EncodeUint64(transferValue)
	transferGasPriceHex      = hexutil.EncodeUint64(transferGasPrice)
	transferGasLimitHex      = hexutil.EncodeUint64(transferGasLimit)
	transferGasLimitERC20Hex = hexutil.EncodeUint64(transferGasLimitERC20)
	transferNonceHex         = hexutil.EncodeUint64(transferNonce)
	transferNonceHex2        = "0x22"
)

func forceHexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("could not decode hex %s", s)
	}

	return b
}

func forceMarshalMap(t *testing.T, i interface{}) map[string]interface{} {
	m, err := marshalJSONMap(i)
	if err != nil {
		t.Fatalf("could not marshal map %s", types.PrintStruct(i))
	}

	return m
}

func TestConstructionService(t *testing.T) {
	networkIdentifier = &types.NetworkIdentifier{
		Network:    optimism.TestnetNetwork,
		Blockchain: optimism.Blockchain,
	}

	cfg := &configuration.Configuration{
		Mode:    configuration.Online,
		Network: networkIdentifier,
		Params:  params.TestnetChainConfig,
	}

	mockClient := &mocks.Client{}
	servicer := NewConstructionAPIService(cfg, mockClient)
	ctx := context.Background()

	// Test Derive
	publicKey := &types.PublicKey{
		Bytes: forceHexDecode(
			t,
			"03d3d3358e7f69cbe45bde38d7d6f24660c7eeeaee5c5590cfab985c8839b21fd5",
		),
		CurveType: types.Secp256k1,
	}
	deriveResponse, err := servicer.ConstructionDerive(ctx, &types.ConstructionDeriveRequest{
		NetworkIdentifier: networkIdentifier,
		PublicKey:         publicKey,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionDeriveResponse{
		AccountIdentifier: &types.AccountIdentifier{
			Address: "0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309",
		},
	}, deriveResponse)

	// Test Preprocess
	intent := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},"amount":{"value":"-42894881044106498","currency":{"symbol":"ETH","decimals":18}}},{"operation_identifier":{"index":1},"type":"CALL","account":{"address":"0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d"},"amount":{"value":"42894881044106498","currency":{"symbol":"ETH","decimals":18}}}]` // nolint
	var ops []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(intent), &ops))
	preprocessResponse, err := servicer.ConstructionPreprocess(
		ctx,
		&types.ConstructionPreprocessRequest{
			NetworkIdentifier: networkIdentifier,
			Operations:        ops,
		},
	)
	assert.Nil(t, err)
	optionsRaw := `{"from":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309", "to":"0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d", "value": "0x9864aac3510d02"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, &options),
	}, preprocessResponse)

	// Test Metadata
	metadata := &metadata{
		GasLimit: big.NewInt(21000),
		GasPrice: big.NewInt(1000000000),
		Nonce:    0,
		To:       "0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d",
		Value:    big.NewInt(42894881044106498),
	}

	mockClient.On(
		"SuggestGasPrice",
		ctx,
	).Return(
		big.NewInt(1000000000),
		nil,
	).Once()
	mockClient.On(
		"PendingNonceAt",
		ctx,
		common.HexToAddress("0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"),
	).Return(
		uint64(0),
		nil,
	).Once()
	metadataResponse, err := servicer.ConstructionMetadata(ctx, &types.ConstructionMetadataRequest{
		NetworkIdentifier: networkIdentifier,
		Options:           forceMarshalMap(t, &options),
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionMetadataResponse{
		Metadata: forceMarshalMap(t, metadata),
		SuggestedFee: []*types.Amount{
			{
				Value:    "21000000000000",
				Currency: optimism.Currency,
			},
		},
	}, metadataResponse)

	// Test Payloads
	unsignedRaw := `{"from":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309","to":"0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d","value":"0x9864aac3510d02","data":"0x","nonce":"0x0","gas_price":"0x3b9aca00","gas":"0x5208","chain_id":"0x3"}` // nolint
	payloadsResponse, err := servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, metadata),
	})
	assert.Nil(t, err)
	payloadsRaw := `[{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309","hex_bytes":"b682f3e39c512ff57471f482eab264551487320cbd3b34485f4779a89e5612d1","account_identifier":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},"signature_type":"ecdsa_recovery"}]` // nolint
	var payloads []*types.SigningPayload
	assert.NoError(t, json.Unmarshal([]byte(payloadsRaw), &payloads))
	assert.Equal(t, &types.ConstructionPayloadsResponse{
		UnsignedTransaction: unsignedRaw,
		Payloads:            payloads,
	}, payloadsResponse)

	// Test Parse Unsigned
	parseOpsRaw := `[{"operation_identifier":{"index":0},"type":"CALL","account":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},"amount":{"value":"-42894881044106498","currency":{"symbol":"ETH","decimals":18}}},{"operation_identifier":{"index":1},"related_operations":[{"index":0}],"type":"CALL","account":{"address":"0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d"},"amount":{"value":"42894881044106498","currency":{"symbol":"ETH","decimals":18}}}]` // nolint
	var parseOps []*types.Operation
	assert.NoError(t, json.Unmarshal([]byte(parseOpsRaw), &parseOps))
	parseUnsignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            false,
		Transaction:       unsignedRaw,
	})
	assert.Nil(t, err)
	parseMetadata := &parseMetadata{
		Nonce:    metadata.Nonce,
		GasPrice: metadata.GasPrice,
		GasLimit: metadata.GasLimit.Uint64(),
		ChainID:  big.NewInt(3),
	}
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations:               parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{},
		Metadata:                 forceMarshalMap(t, parseMetadata),
	}, parseUnsignedResponse)

	// Test Combine
	signaturesRaw := `[{"hex_bytes":"8c712c64bc65c4a88707fa93ecd090144dffb1bf133805a10a51d354c2f9f2b25a63cea6989f4c58372c41f31164036a6b25dce1d5c05e1d31c16c0590c176e801","signing_payload":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309","hex_bytes":"b682f3e39c512ff57471f482eab264551487320cbd3b34485f4779a89e5612d1","account_identifier":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},"signature_type":"ecdsa_recovery"},"public_key":{"hex_bytes":"03d3d3358e7f69cbe45bde38d7d6f24660c7eeeaee5c5590cfab985c8839b21fd5","curve_type":"secp256k1"},"signature_type":"ecdsa_recovery"}]` // nolint
	var signatures []*types.Signature
	assert.NoError(t, json.Unmarshal([]byte(signaturesRaw), &signatures))
	// The tx hash isn't computed on l2geth right now
	//signedRaw := `{"type":"0x0","nonce":"0x0","gasPrice":"0x3b9aca00","maxPriorityFeePerGas":null,"maxFeePerGas":null,"gas":"0x5208","value":"0x9864aac3510d02","input":"0x","v":"0x2a","r":"0x8c712c64bc65c4a88707fa93ecd090144dffb1bf133805a10a51d354c2f9f2b2","s":"0x5a63cea6989f4c58372c41f31164036a6b25dce1d5c05e1d31c16c0590c176e8","to":"0x57b414a0332b5cab885a451c2a28a07d1e9b8a8d","hash":"0x424969b1a98757bcd748c60bad2a7de9745cfb26bfefb4550e780a098feada42"}` // nolint
	signedRaw := `{"nonce":"0x0","gasPrice":"0x3b9aca00","gas":"0x5208","to":"0x57b414a0332b5cab885a451c2a28a07d1e9b8a8d","value":"0x9864aac3510d02","input":"0x","v":"0x2a","r":"0x8c712c64bc65c4a88707fa93ecd090144dffb1bf133805a10a51d354c2f9f2b2","s":"0x5a63cea6989f4c58372c41f31164036a6b25dce1d5c05e1d31c16c0590c176e8","hash":null}`
	combineResponse, err := servicer.ConstructionCombine(ctx, &types.ConstructionCombineRequest{
		NetworkIdentifier:   networkIdentifier,
		UnsignedTransaction: unsignedRaw,
		Signatures:          signatures,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionCombineResponse{
		SignedTransaction: signedRaw,
	}, combineResponse)

	// Test Parse Signed
	parseSignedResponse, err := servicer.ConstructionParse(ctx, &types.ConstructionParseRequest{
		NetworkIdentifier: networkIdentifier,
		Signed:            true,
		Transaction:       signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.ConstructionParseResponse{
		Operations: parseOps,
		AccountIdentifierSigners: []*types.AccountIdentifier{
			{Address: "0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},
		},
		Metadata: forceMarshalMap(t, parseMetadata),
	}, parseSignedResponse)

	// Test Hash
	transactionIdentifier := &types.TransactionIdentifier{
		Hash: "0x424969b1a98757bcd748c60bad2a7de9745cfb26bfefb4550e780a098feada42",
	}
	hashResponse, err := servicer.ConstructionHash(ctx, &types.ConstructionHashRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, hashResponse)

	// Test Submit
	mockClient.On(
		"SendTransaction",
		ctx,
		mock.Anything, // can't test ethTx here because it contains "time"
	).Return(
		nil,
	)
	submitResponse, err := servicer.ConstructionSubmit(ctx, &types.ConstructionSubmitRequest{
		NetworkIdentifier: networkIdentifier,
		SignedTransaction: signedRaw,
	})
	assert.Nil(t, err)
	assert.Equal(t, &types.TransactionIdentifierResponse{
		TransactionIdentifier: transactionIdentifier,
	}, submitResponse)

	mockClient.AssertExpectations(t)
}

func TestMetadata_Offline(t *testing.T) {
	t.Run("unavailable in offline mode", func(t *testing.T) {
		service := ConstructionAPIService{
			config: &configuration.Configuration{Mode: configuration.Offline},
		}

		resp, err := service.ConstructionMetadata(
			context.Background(),
			&types.ConstructionMetadataRequest{},
		)
		assert.Nil(t, resp)
		assert.Equal(t, ErrUnavailableOffline.Code, err.Code)
	})
}

func TestMetadata(t *testing.T) {
	var (
		metadataFrom        = fromAddress
		metadataTo          = toAddress
		metadataData        = transferData
		metadataGenericData = "0x095ea7b3000000000000000000000000d10a72cf054650931365cc44d912a4fd7525705800000000000000000000000000000000000000000000000000000000000003e8"
	)

	var tests = map[string]struct {
		options          map[string]interface{}
		mocks            func(context.Context, *mocks.Client)
		expectedResponse *types.ConstructionMetadataResponse
		expectedError    *types.Error
	}{
		"happy path: native currency with nonce": {
			options: map[string]interface{}{
				"from":  metadataFrom,
				"to":    metadataTo,
				"value": transferValueHex,
				"nonce": transferNonceHex2,
			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":        metadataTo,
					"value":     transferValueHex,
					"nonce":     transferNonceHex2,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitHex,
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasPrice*transferGasLimit),
						Currency: optimism.Currency,
					},
				},
			},
			mocks: func(ctx context.Context, client *mocks.Client) {
				client.On("SuggestGasPrice", ctx).
					Return(big.NewInt(int64(transferGasPrice)), nil)
			},
		},
		"happy path: native currency without nonce": {
			options: map[string]interface{}{
				"from":  metadataFrom,
				"to":    metadataTo,
				"value": transferValueHex,
			},
			mocks: func(ctx context.Context, client *mocks.Client) {
				client.On("PendingNonceAt", ctx, common.HexToAddress(metadataFrom)).
					Return(transferNonce, nil)

				client.On("SuggestGasPrice", ctx).
					Return(big.NewInt(int64(transferGasPrice)), nil)
			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":        metadataTo,
					"value":     transferValueHex,
					"nonce":     transferNonceHex,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitHex,
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasPrice*transferGasLimit),
						Currency: optimism.Currency,
					},
				},
			},
		},
		"happy path: ERC20 currency with nonce": {
			options: map[string]interface{}{
				"from":          metadataFrom,
				"to":            metadataTo,
				"value":         "0x0",
				"nonce":         transferNonceHex2,
				"token_address": tokenContractAddress,
				"data":          metadataData,
			},
			mocks: func(ctx context.Context, client *mocks.Client) {
				to := common.HexToAddress(tokenContractAddress)
				dataBytes, _ := hexutil.Decode(metadataData)
				client.On("EstimateGas", ctx, ethereum.CallMsg{
					From: common.HexToAddress(metadataFrom),
					To:   &to,
					Data: dataBytes,
				}).Return(transferGasLimitERC20, nil)

				client.On("SuggestGasPrice", ctx).
					Return(big.NewInt(int64(transferGasPrice)), nil)
			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":        tokenContractAddress,
					"value":     "0x0",
					"nonce":     transferNonceHex2,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitERC20Hex,
					"data":      metadataData,
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasPrice*transferGasLimitERC20),
						Currency: optimism.Currency,
					},
				},
			},
		},
		"happy path: Generic contract call metadata": {
			options: map[string]interface{}{
				"from":             metadataFrom,
				"to":               metadataTo,
				"value":            "0x0",
				"nonce":            transferNonceHex2,
				"contract_address": tokenContractAddress,
				"data":             metadataGenericData,
				"method_signature": "approve(address,uint256)",
				"method_args":      []string{"0xD10a72Cf054650931365Cc44D912a4FD75257058", "1000"},
			},
			mocks: func(ctx context.Context, client *mocks.Client) {
				to := common.HexToAddress(tokenContractAddress)
				dataBytes, _ := hexutil.Decode(metadataGenericData)
				client.On("EstimateGas", ctx, ethereum.CallMsg{
					From: common.HexToAddress(metadataFrom),
					To:   &to,
					Data: dataBytes,
				}).Return(transferGasLimitERC20, nil)

				client.On("SuggestGasPrice", ctx).
					Return(big.NewInt(int64(transferGasPrice)), nil)
			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":               tokenContractAddress,
					"value":            "0x0",
					"nonce":            transferNonceHex2,
					"gas_price":        transferGasPriceHex,
					"gas_limit":        transferGasLimitERC20Hex,
					"data":             metadataGenericData,
					"method_signature": "approve(address,uint256)",
					"method_args":      []interface{}{"0xD10a72Cf054650931365Cc44D912a4FD75257058", "1000"},
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", transferGasPrice*transferGasLimitERC20),
						Currency: optimism.Currency,
					},
				},
			},
		},
		"error: missing source address": {
			options: map[string]interface{}{
				"to":    metadataTo,
				"nonce": transferNonceHex2,
				"value": transferValueHex,
			},
			expectedResponse: nil,
			expectedError: templateError(
				ErrInvalidAddress, "source address is not provided"),
		},
		"error: invalid source address": {
			options: map[string]interface{}{
				"from":  "invalid_from",
				"to":    metadataTo,
				"nonce": transferNonceHex2,
				"value": transferValueHex,
			},
			expectedResponse: nil,
			expectedError: templateError(
				ErrInvalidAddress, "invalid_from is not a valid address"),
		},
		"error: missing destination address": {
			options: map[string]interface{}{
				"from":  metadataFrom,
				"nonce": transferNonceHex,
				"value": transferValueHex,
			},
			expectedResponse: nil,
			expectedError: templateError(
				ErrInvalidAddress, "destination address is not provided"),
		},
		"error: invalid destination address": {
			options: map[string]interface{}{
				"from":  metadataFrom,
				"to":    "invalid_to",
				"nonce": transferNonceHex,
				"value": transferValueHex,
			},
			expectedResponse: nil,
			expectedError: templateError(
				ErrInvalidAddress, "invalid_to is not a valid address"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			mockClient := &mocks.Client{}
			service := NewConstructionAPIService(
				&configuration.Configuration{Mode: configuration.Online},
				mockClient,
			)

			if test.mocks != nil {
				test.mocks(context.Background(), mockClient)
			}

			resp, err := service.ConstructionMetadata(context.Background(), &types.ConstructionMetadataRequest{
				NetworkIdentifier: networkIdentifier,
				Options:           test.options,
			})

			if err != nil {
				assert.Equal(t, test.expectedError, err)
			} else {
				assert.Equal(t, test.expectedResponse, resp)
			}
		})
	}

}

func templateError(error *types.Error, context string) *types.Error {
	return &types.Error{
		Code:      error.Code,
		Message:   error.Message,
		Retriable: false,
		Details: map[string]interface{}{
			"context": context,
		},
	}
}
