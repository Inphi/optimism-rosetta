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
	"encoding/json"
	"math/big"
	"testing"

	EthCommon "github.com/ethereum/go-ethereum/common"
	EthHexutil "github.com/ethereum/go-ethereum/common/hexutil"

	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"

	"github.com/stretchr/testify/suite"
)

type ClientBedrockTxTestSuite struct {
	suite.Suite

	mockJSONRPC         *mocks.JSONRPC
	mockGraphQL         *mocks.GraphQL
	mockCurrencyFetcher *mocks.CurrencyFetcher
}

func TestClientBedrockTx(t *testing.T) {
	suite.Run(t, new(ClientBedrockTxTestSuite))
}

func (testSuite *ClientBedrockTxTestSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
	testSuite.mockCurrencyFetcher = &mocks.CurrencyFetcher{}
}

// Test transaction deserialization
func (testSuite *ClientBedrockTxTestSuite) TestTransactionDeserialization() {
	// Construct the expected transactions
	expectedBlockNumber := "0x4c5836"
	expectedBlockHash := EthCommon.HexToHash("0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774")
	expectedTransactionFrom := EthCommon.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001")
	expectedTxHash := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	data := EthCommon.Hex2Bytes("015d8eb900000000000000000000000000000000000000000000000000000000008097790000000000000000000000000000000000000000000000000000000063dd1a98000000000000000000000000000000000000000000000000000000000004ee2f1ed96835176d084c845bd2c09456d60401d74861b690bdabac97f6724f4b4bdf00000000000000000000000000000000000000000000000000000000000000020000000000000000000000007431310e026b69bfc676c0013e12a1a11411eec9000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240")
	recipient := EthCommon.HexToAddress("0x4200000000000000000000000000000000000015")
	nonce := uint64(0)
	expectedTransaction := BedrockRPCTransaction{
		Tx: &transaction{
			Type:                 (EthHexutil.Uint64)(convertBigInt("0x7e").Uint64()),
			Nonce:                (*EthHexutil.Uint64)(&nonce),
			Price:                (*EthHexutil.Big)(nil),
			MaxPriorityFeePerGas: (*EthHexutil.Big)(nil),
			MaxFeePerGas:         (*EthHexutil.Big)(nil),
			GasLimit:             (EthHexutil.Uint64)(convertBigInt("0x8f0d180").Uint64()),
			Value:                (*EthHexutil.Big)(nil),
			Data:                 (*EthHexutil.Bytes)(&data),
			V:                    (*EthHexutil.Big)(nil),
			R:                    (*EthHexutil.Big)(nil),
			S:                    (*EthHexutil.Big)(nil),
			Recipient:            &recipient,
			ChainID:              (*EthHexutil.Big)(nil),
			HashValue:            expectedTxHash,
		},
		TxExtraInfo: TxExtraInfo{
			BlockNumber: &expectedBlockNumber,
			BlockHash:   &expectedBlockHash,
			From:        &expectedTransactionFrom,
			TxHash:      &expectedTxHash,
		},
	}

	// Marshal the expected transaction
	rawTransaction := `{
		"blockHash": "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774",
		"blockNumber": "0x4c5836",
		"from": "0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001",
		"gas": "0x8f0d180",
		"gasPrice": null,
		"hash": "0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611",
		"input": "0x015d8eb900000000000000000000000000000000000000000000000000000000008097790000000000000000000000000000000000000000000000000000000063dd1a98000000000000000000000000000000000000000000000000000000000004ee2f1ed96835176d084c845bd2c09456d60401d74861b690bdabac97f6724f4b4bdf00000000000000000000000000000000000000000000000000000000000000020000000000000000000000007431310e026b69bfc676c0013e12a1a11411eec9000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240",
		"isSystemTx": true,
		"mint": "0x0",
		"nonce": "0x0",
		"r": null,
		"s": null,
		"sourceHash": "0xe498acd8ac4c577ba87349e5f649034404485515ba7f2fa3b8dfda726dd62c16",
		"to": "0x4200000000000000000000000000000000000015",
		"transactionIndex": "0x0",
		"type": "0x7e",
		"v": null,
		"value": null
	}`

	// Unmarshal the expected transaction
	var expectedTransactionUnmarshalled BedrockRPCTransaction
	err := json.Unmarshal([]byte(rawTransaction), &expectedTransactionUnmarshalled)
	testSuite.NoError(err)

	// Compare the expected transaction with the unmarshalled one
	testSuite.Equal(expectedTransaction, expectedTransactionUnmarshalled)
}

// Test transaction deserialization with an empty body
func (testSuite *ClientBedrockTxTestSuite) TestTransactionDeserializationStripped() {
	// Construct the expected transactions
	expectedTransaction := BedrockRPCTransaction{
		Tx: &transaction{
			Type:                 (EthHexutil.Uint64)(0),
			Nonce:                (*EthHexutil.Uint64)(nil),
			Price:                (*EthHexutil.Big)(nil),
			MaxPriorityFeePerGas: (*EthHexutil.Big)(nil),
			MaxFeePerGas:         (*EthHexutil.Big)(nil),
			GasLimit:             (EthHexutil.Uint64)(0),
			Value:                (*EthHexutil.Big)(nil),
			Data:                 (*EthHexutil.Bytes)(nil),
			V:                    (*EthHexutil.Big)(nil),
			R:                    (*EthHexutil.Big)(nil),
			S:                    (*EthHexutil.Big)(nil),
			Recipient:            nil,
			ChainID:              (*EthHexutil.Big)(nil),
			HashValue:            (EthCommon.Hash)([32]byte{}),
		},
		TxExtraInfo: TxExtraInfo{
			BlockNumber: nil,
			BlockHash:   (*EthCommon.Hash)(nil),
			From:        (*EthCommon.Address)(nil),
			TxHash:      (*EthCommon.Hash)(nil),
		},
	}

	// Marshal the expected transaction
	rawTransaction := `{}`

	// Unmarshal the expected transaction
	var expectedTransactionUnmarshalled BedrockRPCTransaction
	err := json.Unmarshal([]byte(rawTransaction), &expectedTransactionUnmarshalled)
	testSuite.NoError(err)

	// Compare the expected transaction with the unmarshalled one
	testSuite.Equal(expectedTransaction, expectedTransactionUnmarshalled)
}

// Test transaction methods
func (testSuite *ClientBedrockTxTestSuite) TestTransactionMethods() {
	// Construct the expected transactions
	expectedTxHash := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	data := EthCommon.Hex2Bytes("015d8eb900000000000000000000000000000000000000000000000000000000008097790000000000000000000000000000000000000000000000000000000063dd1a98000000000000000000000000000000000000000000000000000000000004ee2f1ed96835176d084c845bd2c09456d60401d74861b690bdabac97f6724f4b4bdf00000000000000000000000000000000000000000000000000000000000000020000000000000000000000007431310e026b69bfc676c0013e12a1a11411eec9000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240")
	recipient := EthCommon.HexToAddress("0x4200000000000000000000000000000000000015")
	nonce := uint64(0)
	expectedType := convertBigInt("0x7e").Uint64()
	expectedValue := convertBigInt("0x69")
	expectedMaxFeePerGas := convertBigInt("0x420")
	expectedMaxPriorityFeePerGas := convertBigInt("0x422")
	expectedGasPrice := convertBigInt("0x421")
	expectedGasLimit := convertBigInt("0x8f0d180").Uint64()
	tx := &transaction{
		Type:                 (EthHexutil.Uint64)(expectedType),
		Nonce:                (*EthHexutil.Uint64)(&nonce),
		Price:                (*EthHexutil.Big)(expectedGasPrice),
		MaxPriorityFeePerGas: (*EthHexutil.Big)(expectedMaxPriorityFeePerGas),
		MaxFeePerGas:         (*EthHexutil.Big)(expectedMaxFeePerGas),
		GasLimit:             (EthHexutil.Uint64)(expectedGasLimit),
		Value:                (*EthHexutil.Big)(expectedValue),
		Data:                 (*EthHexutil.Bytes)(&data),
		V:                    (*EthHexutil.Big)(nil),
		R:                    (*EthHexutil.Big)(nil),
		S:                    (*EthHexutil.Big)(nil),
		Recipient:            &recipient,
		ChainID:              (*EthHexutil.Big)(nil),
		HashValue:            expectedTxHash,
	}

	// Check method calls
	testSuite.True(tx.IsDepositTx())
	testSuite.Equal(expectedType, tx.GetType())
	testSuite.Equal(expectedValue, tx.GetValue())
	testSuite.Equal(expectedTxHash, tx.Hash())
	testSuite.Equal(&recipient, tx.To())
	testSuite.Equal(expectedGasLimit, tx.Gas())
	testSuite.Equal(expectedGasPrice, tx.GasPrice())
	testSuite.Equal(expectedMaxPriorityFeePerGas, tx.GasTipCap())
	testSuite.Equal(expectedMaxFeePerGas, tx.GasFeeCap())
}

// TestTransactionNilMethodReturns ensures transaction methods return nil when the transaction is gas price is nil
func (testSuite *ClientBedrockTxTestSuite) TestTransactionNilMethodReturns() {
	// Construct an empty transaction
	tx := &transaction{}
	var nilRecipient *EthCommon.Address

	// Check gas price is not nil
	testSuite.Equal(big.NewInt(0), tx.GasPrice())
	testSuite.Equal(nilRecipient, tx.To())
	testSuite.False(tx.IsDepositTx())
}
