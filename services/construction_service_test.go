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
	"strings"
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
	chainID    = uint64(69)
	chainIDHex = hexutil.EncodeUint64(chainID)

	fromAddress          = "0x14791697260E4c9A71f18484C9f997B308e59325"
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

	delegateData     = "0x5c19a95c000000000000000000000000705f9ae78b11a3ed5080c053fa4fa0c52359c674"
	delegatee        = "0x705f9ae78b11a3ed5080c053fa4fa0c52359c674"
	delegateGasPrice = transferGasPrice
	delegateGasLimit = transferGasLimitERC20
	delegateNonce    = transferNonce

	delegateNonceHex    = hexutil.EncodeUint64(delegateNonce)
	delegateGasPriceHex = hexutil.EncodeUint64(delegateGasPrice)
	delegateGasLimitHex = hexutil.EncodeUint64(delegateGasLimit)
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
	var opts options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &opts))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, &opts),
	}, preprocessResponse)

	// Test Metadata
	metadata := &metadata{
		GasLimit: 21000,
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
		Options:           forceMarshalMap(t, &opts),
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

	// Test Payloads for case-insentive addresses
	unsignedRaw = `{"from":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309","to":"0x57B414a0332B5CaB885a451c2a28a07d1e9b8a8d","value":"0x9864aac3510d02","data":"0x","nonce":"0x0","gas_price":"0x3b9aca00","gas":"0x5208","chain_id":"0x3"}` // nolint
	m := *metadata
	m.To = strings.ToUpper(m.To)
	payloadsResponse, err = servicer.ConstructionPayloads(ctx, &types.ConstructionPayloadsRequest{
		NetworkIdentifier: networkIdentifier,
		Operations:        ops,
		Metadata:          forceMarshalMap(t, &m),
	})
	assert.Nil(t, err)
	payloadsRaw = `[{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309","hex_bytes":"b682f3e39c512ff57471f482eab264551487320cbd3b34485f4779a89e5612d1","account_identifier":{"address":"0xe3a5B4d7f79d64088C8d4ef153A7DDe2B2d47309"},"signature_type":"ecdsa_recovery"}]` // nolint
	payloads = nil
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
		GasLimit: metadata.GasLimit,
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
		"happy path: ERC20Votes delegation without nonce": {
			options: map[string]interface{}{
				"from":          metadataFrom,
				"to":            delegatee,
				"value":         "0x0",
				"token_address": tokenContractAddress,
				"data":          delegateData,
			},
			mocks: func(ctx context.Context, client *mocks.Client) {
				client.On("PendingNonceAt", ctx, common.HexToAddress(metadataFrom)).
					Return(delegateNonce, nil)

				client.On("SuggestGasPrice", ctx).
					Return(big.NewInt(int64(delegateGasPrice)), nil)

				to := common.HexToAddress(tokenContractAddress)
				client.On("EstimateGas", ctx, ethereum.CallMsg{
					From: common.HexToAddress(metadataFrom),
					To:   &to,
					Data: hexutil.MustDecode(delegateData),
				}).Return(delegateGasLimit, nil)
			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":        tokenContractAddress,
					"value":     "0x0",
					"nonce":     delegateNonceHex,
					"gas_price": delegateGasPriceHex,
					"gas_limit": delegateGasLimitHex,
					"data":      delegateData,
				},
				SuggestedFee: []*types.Amount{
					{
						Value:    fmt.Sprintf("%d", delegateGasPrice*delegateGasLimit),
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
		"happy path: Generic contract call with value": {
			options: map[string]interface{}{
				"from":             metadataFrom,
				"to":               metadataTo,
				"value":            "0x5f5e100",
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
					From:  common.HexToAddress(metadataFrom),
					To:    &to,
					Data:  dataBytes,
					Value: big.NewInt(100000000),
				}).Return(transferGasLimitERC20, nil)

				client.On("SuggestGasPrice", ctx).
					Return(big.NewInt(int64(transferGasPrice)), nil)
			},
			expectedResponse: &types.ConstructionMetadataResponse{
				Metadata: map[string]interface{}{
					"to":               tokenContractAddress,
					"value":            "0x5f5e100",
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

func TestParse(t *testing.T) {
	var (
		unsignedOPTransferTx            = `{"from":"0x14791697260E4c9A71f18484C9f997B308e59325","to":"0xefD3dc58D60aF3295B92ecd484CAEB3A2f30b3e7","value":"0x134653c","data":"0x","nonce":"0x43","gas_price":"0x12a05f200","gas":"0x5208","chain_id":"0x45"}`                                                                                                                                                                                                                                                                                                      //nolint:lll
		signedOPTransferTx              = `{"nonce":"0x43","gasPrice":"0x12a05f200","gas":"0x5208","to":"0xefd3dc58d60af3295b92ecd484caeb3a2f30b3e7","value":"0x134653c","input":"0x","v":"0xad","r":"0xb01f5371d2d9bf33e17b910ea262cce459e2503bf6355b0fc45b6ef1582facb6","s":"0x37c813abca8ba5962dc7808ba9305544980c19208bf6fcde2fe8a66f2bab4ebc","hash":"0x3ace0a1d293b99f2ad4083a17b19f3b204858b051dc235802346bf0b73d34b09"}`                                                                                                                                   //nolint:lll
		unsignedERC20TransferTx         = `{"from":"0x14791697260E4c9A71f18484C9f997B308e59325","to":"0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e","value":"0x0","data":"0xa9059cbb000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c","nonce":"0x43","gas_price":"0x12a05f200","gas":"0xfde8","chain_id":"0x45"}`                                                                                                                                                                    //nolint:lll
		signedERC20TransferTx           = `{"nonce":"0x43","gasPrice":"0x12a05f200","gas":"0xfde8","to":"0x2d7882bedcbfddce29ba99965dd3cdf7fcb10a1e","value":"0x0","input":"0xa9059cbb000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7000000000000000000000000000000000000000000000000000000000134653c","v":"0xad","r":"0x4c920b7e6480d06e4c89da9dbefa97ba1a2ff342c8843a0dc5c0ff15bab3f20b","s":"0x241aa86941f6adea2f048e0741fba77bda880772e95555347dbabaeca8450767","hash":"0x4fa571a8450dae225492ea11dffc5c89ca328f751cedac0e43e4e0919aaf8297"}` //nolint:lll
		unsignedOPTransferTxInvalidFrom = `{"from":"invalid_from","to":"0xefD3dc58D60aF3295B92ecd484CAEB3A2f30b3e7","value":"0x134653c","data":"0x","nonce":"0x43","gas_price":"0x12a05f200","gas":"0x5208","chain_id":"0x45"}`                                                                                                                                                                                                                                                                                                                                    //nolint:lll
		unsignedOPTransferTxInvalidTo   = `{"from":"0x14791697260E4c9A71f18484C9f997B308e59325","to":"invalid_to","value":"0x134653c","data":"0x","nonce":"0x43","gas_price":"0x12a05f200","gas":"0x5208","chain_id":"0x45"}`                                                                                                                                                                                                                                                                                                                                      //nolint:lll
		unsignedERC20VotesDelegateTx    = `{"from":"0x14791697260E4c9A71f18484C9f997B308e59325","to":"0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e","value":"0x0","data":"0x5c19a95c000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7","nonce":"0x43","gas_price":"0x12a05f200","gas":"0xfde8","chain_id":"0x45"}`                                                                                                                                                                                                                                    //nolint:lll
		delegateSignerAddress           = "0xc5e5C23544113877F7fF09B4Fe9B8CcE41ea3C49"
		signedERC20VotesDelegateTx      = `{"from":"0xc5e5C23544113877F7fF09B4Fe9B8CcE41ea3C49","to":"0x2d7882beDcbfDDce29Ba99965dd3cdF7fcB10A1e","value":"0x0","input":"0x5c19a95c000000000000000000000000efd3dc58d60af3295b92ecd484caeb3a2f30b3e7","nonce":"0x43","gasPrice":"0x12a05f200","gas":"0xfde8","chain_id":"0x45","v":"0xad","r":"0x3e86670c25c42e1735b770a0cbea2276ce1771bff7401f3e7087f6296f187d2a","s":"0x52e9934a1efddf5f55073eb6aa4638a131ca2c2e482bce2ab9a0b13ff45547f8","hash":"0x4fa571a8450dae225492ea11dffc5c89ca328f751cedac0e43e4e0919aaf8297"}` //nolint:lll
	)

	tests := map[string]struct {
		request          *types.ConstructionParseRequest
		expectedResponse *types.ConstructionParseResponse
		expectedError    *types.Error
	}{
		"happy path: unsigned OP transfer tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       unsignedOPTransferTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations:               templateOperations(transferValue, optimism.Currency, false),
				AccountIdentifierSigners: []*types.AccountIdentifier{},
				Metadata: map[string]interface{}{
					"nonce":     transferNonceHex,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitHex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"happy path: signed OP transfer tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            true,
				Transaction:       signedOPTransferTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations: templateOperations(transferValue, optimism.Currency, false),
				AccountIdentifierSigners: []*types.AccountIdentifier{
					{
						Address: fromAddress,
					},
				},
				Metadata: map[string]interface{}{
					"nonce":     transferNonceHex,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitHex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"happy path: unsigned ERC20 transfer tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       unsignedERC20TransferTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations: templateOperations(transferValue, &types.Currency{
					Symbol:   "OP",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": tokenContractAddress,
					},
				}, true),
				AccountIdentifierSigners: []*types.AccountIdentifier{},
				Metadata: map[string]interface{}{
					"nonce":     transferNonceHex,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitERC20Hex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"happy path: signed ERC20 transfer tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            true,
				Transaction:       signedERC20TransferTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations: templateOperations(transferValue, &types.Currency{
					Symbol:   "OP",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": tokenContractAddress,
					},
				}, true),
				AccountIdentifierSigners: []*types.AccountIdentifier{
					{
						Address: fromAddress,
					},
				},
				Metadata: map[string]interface{}{
					"nonce":     transferNonceHex,
					"gas_price": transferGasPriceHex,
					"gas_limit": transferGasLimitERC20Hex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"happy path: unsigned ERC20Votes delegate tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       unsignedERC20VotesDelegateTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations: templateDelegateOperations(fromAddress, &types.Currency{
					Symbol:   "OP",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": tokenContractAddress,
					},
				}),
				AccountIdentifierSigners: []*types.AccountIdentifier{},
				Metadata: map[string]interface{}{
					"nonce":     delegateNonceHex,
					"gas_price": delegateGasPriceHex,
					"gas_limit": delegateGasLimitHex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"happy path: signed ERC20Votes delegate tx": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            true,
				Transaction:       signedERC20VotesDelegateTx,
			},
			expectedResponse: &types.ConstructionParseResponse{
				Operations: templateDelegateOperations(delegateSignerAddress, &types.Currency{
					Symbol:   "OP",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": tokenContractAddress,
					},
				}),
				AccountIdentifierSigners: []*types.AccountIdentifier{{Address: delegateSignerAddress}},
				Metadata: map[string]interface{}{
					"nonce":     delegateNonceHex,
					"gas_price": delegateGasPriceHex,
					"gas_limit": delegateGasLimitHex,
					"chain_id":  chainIDHex,
				},
			},
		},
		"error: empty transaction": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       "",
			},
			expectedError: templateError(
				ErrUnableToParseIntermediateResult, "unexpected end of JSON input"),
		},
		// TODO: Add logic for generic call
		// "error: unable to parse transaction": {
		// 	request: &types.ConstructionParseRequest{
		// 		NetworkIdentifier: networkIdentifier,
		// 		Signed:            false,
		// 		Transaction:       unsignedERC20TransferTxInvalidData,
		// 	},
		// 	expectedError: templateError(
		// 		svcError.ErrUnableToParseTransaction, "invalid method id"),
		// },
		"error: invalid from address": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       unsignedOPTransferTxInvalidFrom,
			},
			expectedError: templateError(
				ErrInvalidAddress, "invalid_from is not a valid address"),
		},
		"error: invalid to address": {
			request: &types.ConstructionParseRequest{
				NetworkIdentifier: networkIdentifier,
				Signed:            false,
				Transaction:       unsignedOPTransferTxInvalidTo,
			},
			expectedError: templateError(
				ErrInvalidAddress, "invalid_to is not a valid address"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := &ConstructionAPIService{}
			resp, err := service.ConstructionParse(context.Background(), test.request)

			if err != nil {
				assert.Equal(t, test.expectedError, err)
			} else {
				assert.Equal(t, test.expectedResponse, resp)
			}
		})
	}
}

func TestPreprocessERC20(t *testing.T) {
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

	intent := `[{"operation_identifier":{"index":0},"type":"PAYMENT","account":{"address":"0x9670d6977d0b10130E5d4916c9134363281B6B0e"},"amount":{"value":"-100000000000","currency":{"symbol":"OP","decimals":18,"metadata":{"token_address":"0xF8B089026CaD7DDD8CB8d79036A1ff1d4233d64A"}}}},{"operation_identifier":{"index":1},"type":"PAYMENT","account":{"address":"0x705f9aE78b11a3ED5080c053Fa4Fa0c52359c674"},"amount":{"value":"100000000000","currency":{"symbol":"OP","decimals":18,"metadata":{"token_address":"0xF8B089026CaD7DDD8CB8d79036A1ff1d4233d64A"}}}}]` // nolint
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
	optionsRaw := `{"from":"0x9670d6977d0b10130E5d4916c9134363281B6B0e", "to":"0x705f9aE78b11a3ED5080c053Fa4Fa0c52359c674", "data":"0xa9059cbb000000000000000000000000705f9ae78b11a3ed5080c053fa4fa0c52359c674000000000000000000000000000000000000000000000000000000174876e800", "token_address":"0xF8B089026CaD7DDD8CB8d79036A1ff1d4233d64A", "value": "0x0"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, &options),
	}, preprocessResponse)
}

func TestPreprocessGovernanceDelegate(t *testing.T) {
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

	intent := `
[
  {
    "operation_identifier": {
      "index": 0
    },
    "type": "DELEGATE_VOTES",
    "account": {
      "address": "0x9670d6977d0b10130E5d4916c9134363281B6B0e"
    },
    "amount": {
      "value": "0",
      "currency": {
        "symbol": "OP",
        "decimals": 18,
        "metadata": {
          "token_address": "0xF8B089026CaD7DDD8CB8d79036A1ff1d4233d64A"
        }
      }
    }
  },
  {
    "operation_identifier": {
      "index": 1
    },
    "type": "DELEGATE_VOTES",
    "account": {
      "address": "0x705f9aE78b11a3ED5080c053Fa4Fa0c52359c674"
    },
    "amount": {
      "value": "0",
      "currency": {
        "symbol": "OP",
        "decimals": 18,
        "metadata": {
          "token_address": "0xF8B089026CaD7DDD8CB8d79036A1ff1d4233d64A"
        }
      }
    }
  }
]` // nolint
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
	optionsRaw := `{"from":"0x9670d6977d0b10130E5d4916c9134363281B6B0e", "to":"0x705f9aE78b11a3ED5080c053Fa4Fa0c52359c674", "data":"0x5c19a95c000000000000000000000000705f9aE78b11a3ED5080c053Fa4Fa0c52359c674", "token_address":"0xF8B089026CaD7DDD8CB8d79036A1ff1d4233d64A", "value": "0x0"}`
	var options options
	assert.NoError(t, json.Unmarshal([]byte(optionsRaw), &options))
	assert.Equal(t, &types.ConstructionPreprocessResponse{
		Options: forceMarshalMap(t, &options),
	}, preprocessResponse)

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

func templateOperations(amount uint64, currency *types.Currency, erc20Transfer bool) []*types.Operation {
	typ := optimism.CallOpType
	if erc20Transfer {
		typ = optimism.PaymentOpType
	}
	return rosettaOperations(
		fromAddress,
		toAddress,
		big.NewInt(int64(amount)),
		currency,
		typ,
	)
}

func templateDelegateOperations(from string, currency *types.Currency) []*types.Operation {
	return rosettaOperations(
		from,
		toAddress, // use the default
		big.NewInt(0),
		currency,
		optimism.DelegateVotesOpType,
	)
}

func TestConstructContractCallData(t *testing.T) {
	tests := map[string]struct {
		methodSig      string
		methodArgs     interface{}
		expectedResult string
	}{
		"transfer": {
			methodSig: "transfer(address,uint256)",
			methodArgs: []string{
				"0xb0935a466e6Fa8FDa8143C7f4a8c149CA56D06FE",
				"173263688900373774",
			},
			expectedResult: "a9059cbb000000000000000000000000b0935a466e6fa8fda8143c7f4a8c149ca56d06fe00000000000000000000000000000000000000000000000002678e6835616d0e",
		},
		"bridge withdraw": {
			methodSig: "withdraw(address,uint256,uint32,bytes)",
			methodArgs: []string{
				"0xDeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000",
				"23535",
				"0",
				"0x",
			},
			expectedResult: "32b7006d000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddead00000000000000000000000000000000000000000000000000000000000000005bef000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000",
		},
		"complex result": {
			methodSig:      "mintItemBatch(address[],string)",
			methodArgs:     "000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000004000000000000000000000000b406c0106ba32281ddfa75626479304feb70d0580000000000000000000000003cdc2ce790d740fd8b8e99baf738497c5e2de62000000000000000000000000006da92f4f1815e83cf5a020f952f0e3275a5b156000000000000000000000000f344767634735d588357ed5828488094bef02efe000000000000000000000000000000000000000000000000000000000000002e516d614b57483933397346454464576333347252395453433868647758624357574575454a6b6476714e334a7573000000000000000000000000000000000000",
			expectedResult: "079c66c0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000004000000000000000000000000b406c0106ba32281ddfa75626479304feb70d0580000000000000000000000003cdc2ce790d740fd8b8e99baf738497c5e2de62000000000000000000000000006da92f4f1815e83cf5a020f952f0e3275a5b156000000000000000000000000f344767634735d588357ed5828488094bef02efe000000000000000000000000000000000000000000000000000000000000002e516d614b57483933397346454464576333347252395453433868647758624357574575454a6b6476714e334a7573000000000000000000000000000000000000",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := constructContractCallData(test.methodSig, test.methodArgs)
			assert.Equal(t, test.expectedResult, hex.EncodeToString(data))
			assert.NoError(t, err)
		})
	}
}
