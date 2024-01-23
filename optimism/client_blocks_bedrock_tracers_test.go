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
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum-optimism/optimism/l2geth/eth"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthHexutil "github.com/ethereum/go-ethereum/common/hexutil"
	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sync/semaphore"
)

var (
	tracerTimeout = "120s"
	loadedTracer  = "callTracer"
	//nolint:unused
	testBedrockTraceConfig = &eth.TraceConfig{
		Timeout: &tracerTimeout,
		Tracer:  &loadedTracer,
	}
)

type BedrockTracersTestSuite struct {
	suite.Suite

	mockJSONRPC         *mocks.JSONRPC
	mockGraphQL         *mocks.GraphQL
	mockCurrencyFetcher *mocks.CurrencyFetcher
}

func (testSuite *BedrockTracersTestSuite) MockJSONRPC() *mocks.JSONRPC {
	return testSuite.mockJSONRPC
}

func (testSuite *BedrockTracersTestSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
	testSuite.mockCurrencyFetcher = &mocks.CurrencyFetcher{}
}

func TestBedrockTracers(t *testing.T) {
	suite.Run(t, new(BedrockTracersTestSuite))
}

func (testSuite *BedrockTracersTestSuite) TestTraceBlockByHash() {
	ctx := context.Background()

	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		tc:              testBedrockTraceConfig,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
		filterTokens:    false,
		bedrockBlock:    big.NewInt(5_003_318),
	}

	tx1 := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	tx2 := EthCommon.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88")
	gasPrice := big.NewInt(10000)
	blockNumber := big.NewInt(1)
	blockNumberString := blockNumber.String()
	to := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")
	myTx := newBedrockTx(
		0,
		to,
		big.NewInt(0),
		0,
		gasPrice,
		nil,
	)
	txs := []BedrockRPCTransaction{
		{
			Tx: myTx,
			TxExtraInfo: TxExtraInfo{
				BlockNumber: &blockNumberString,
				BlockHash:   &tx1,
				From:        &to,
				TxHash:      &tx1,
			},
		},
		{
			Tx: myTx,
			TxExtraInfo: TxExtraInfo{
				BlockNumber: &blockNumberString,
				BlockHash:   &tx2,
				From:        &to,
				TxHash:      &tx2,
			},
		},
	}

	mockTraceBlock(ctx, testSuite, "testdata/goerli_bedrock_block_trace_5003318.json")
	blkHash := EthCommon.HexToHash("0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774")
	m, err := c.TraceBlockByHash(ctx, blkHash, txs)
	testSuite.NoError(err)

	testSuite.Equal(len(m), 2)
	testSuite.NotNil(m[tx1.Hex()])
}

func mockTraceBlock(ctx context.Context, testSuite *BedrockTracersTestSuite, txFileData string) {
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"debug_traceBlockByHash",
		mock.Anything,
		mock.Anything,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := os.ReadFile(txFileData)
			testSuite.NoError(err)
			rawMessage := json.RawMessage(file)
			*r = rawMessage
		},
	).Once()
}

//nolint:unparam
func newBedrockTx(
	nonce uint64,
	to EthCommon.Address,
	amount *big.Int,
	gasLimit uint64,
	gasPrice *big.Int,
	data []byte,
) InnerBedrockTransaction {
	return &transaction{
		Nonce:     (*EthHexutil.Uint64)(&nonce),
		Recipient: &to,
		Value:     (*EthHexutil.Big)(amount),
		GasLimit:  (EthHexutil.Uint64)(gasLimit),
		Price:     (*EthHexutil.Big)(gasPrice),
		Data:      (*EthHexutil.Bytes)(&data),
	}
}

// TestTracedCachedTransaction tests that the trace cache can be used correctly to fetch transaction traces.
func (testSuite *BedrockTracersTestSuite) TestTracedCachedTransaction() {
	ctx := context.Background()

	tspec := tracerSpec{TracerPath: "call_tracer.js", UseGethTracer: true}
	traceCache, err := NewTraceCache(testSuite.mockJSONRPC, tspec, time.Second*120, 10)
	testSuite.NoError(err)

	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		tc:              testBedrockTraceConfig,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
		filterTokens:    false,
		bedrockBlock:    big.NewInt(5_003_318),
		traceCache:      traceCache,
	}

	// Common tx variables
	blockNumber := big.NewInt(1)
	gasPrice := big.NewInt(10000)
	blockNumberString := blockNumber.String()
	blockHash := EthCommon.HexToHash("0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774")
	to := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")

	// Trace the first transaction
	txOneHash := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	txOneBedrockTransaction := newBedrockTx(
		0,
		to,
		big.NewInt(0),
		0,
		gasPrice,
		nil,
	)
	txOneBedrockRPCTransaction := BedrockRPCTransaction{
		Tx: txOneBedrockTransaction,
		TxExtraInfo: TxExtraInfo{
			BlockNumber: &blockNumberString,
			BlockHash:   &blockHash,
			From:        &to,
			TxHash:      &txOneHash,
		},
	}

	// Execute the transaction trace
	mockCachedTraceTransaction(testSuite, txOneHash.Hex(), "testdata/goerli_bedrock_tx_trace_5003318_1.json")
	m, err := c.TraceTransactions(ctx, blockHash, []BedrockRPCTransaction{txOneBedrockRPCTransaction})

	// Expect the result
	expectedCalls := constructTxOneExpectedCalls(m, txOneHash)
	testSuite.NoError(err)
	testSuite.Equal(len(m), 1)
	testSuite.Equal(expectedCalls, m[txOneHash.Hex()])
}

func mockCachedTraceTransaction(testSuite *BedrockTracersTestSuite, txHash string, txFileData string) {
	testSuite.mockJSONRPC.On(
		"CallContext",
		mock.Anything,
		mock.Anything,
		"debug_traceTransaction",
		txHash,
		mock.Anything,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*Call)
			file, err := os.ReadFile(txFileData)
			testSuite.NoError(err)
			call := new(Call)
			testSuite.NoError(call.UnmarshalJSON(file))
			*r = *call
		},
	).Once()
}

// TestErrTracedCachedTransaction tests that a trace cache returning an error should error out.
func (testSuite *BedrockTracersTestSuite) TestErrTracedCachedTransaction() {
	ctx := context.Background()

	tspec := tracerSpec{TracerPath: "call_tracer.js", UseGethTracer: true}
	traceCache, err := NewTraceCache(testSuite.mockJSONRPC, tspec, time.Second*120, 10)
	testSuite.NoError(err)

	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		tc:              testBedrockTraceConfig,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
		filterTokens:    false,
		bedrockBlock:    big.NewInt(5_003_318),
		traceCache:      traceCache,
	}

	// Common tx variables
	blockNumber := big.NewInt(1)
	gasPrice := big.NewInt(10000)
	blockNumberString := blockNumber.String()
	blockHash := EthCommon.HexToHash("0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774")
	to := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")

	// Trace the first transaction
	txOneHash := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	txOneBedrockTransaction := newBedrockTx(
		0,
		to,
		big.NewInt(0),
		0,
		gasPrice,
		nil,
	)
	txOneBedrockRPCTransaction := BedrockRPCTransaction{
		Tx: txOneBedrockTransaction,
		TxExtraInfo: TxExtraInfo{
			BlockNumber: &blockNumberString,
			BlockHash:   &blockHash,
			From:        &to,
			TxHash:      &txOneHash,
		},
	}

	// Execute the transaction trace
	testSuite.mockJSONRPC.On(
		"CallContext",
		mock.Anything,
		mock.Anything,
		"debug_traceTransaction",
		txOneHash.Hex(),
		mock.Anything,
	).Return(
		errors.New("failed to get tx trace"),
	).Once()
	m, err := c.TraceTransactions(ctx, blockHash, []BedrockRPCTransaction{txOneBedrockRPCTransaction})
	testSuite.Error(err)
	testSuite.Nil(m)
}

func (testSuite *BedrockTracersTestSuite) TestTraceTransactions() {
	ctx := context.Background()

	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		tc:              testBedrockTraceConfig,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
		filterTokens:    false,
		bedrockBlock:    big.NewInt(5_003_318),
	}

	// Common tx variables
	blockNumber := big.NewInt(1)
	gasPrice := big.NewInt(10000)
	blockNumberString := blockNumber.String()
	blockHash := EthCommon.HexToHash("0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774")
	to := EthCommon.HexToAddress("095e7baea6a6c7c4c2dfeb977efac326af552d87")

	// Trace the first transaction
	txOneHash := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	txOneBedrockTransaction := newBedrockTx(
		0,
		to,
		big.NewInt(0),
		0,
		gasPrice,
		nil,
	)
	txOneBedrockRPCTransaction := BedrockRPCTransaction{
		Tx: txOneBedrockTransaction,
		TxExtraInfo: TxExtraInfo{
			BlockNumber: &blockNumberString,
			BlockHash:   &blockHash,
			From:        &to,
			TxHash:      &txOneHash,
		},
	}

	// Execute the transaction trace
	mockTraceTransaction(ctx, testSuite, "testdata/goerli_bedrock_tx_trace_5003318_1.json")
	m, err := c.TraceTransactions(ctx, blockHash, []BedrockRPCTransaction{txOneBedrockRPCTransaction})

	// Expect the result
	expectedCalls := constructTxOneExpectedCalls(m, txOneHash)
	testSuite.NoError(err)
	testSuite.Equal(len(m), 1)
	testSuite.Equal(expectedCalls, m[txOneHash.Hex()])

	// Trace the second transaction
	txTwoHash := EthCommon.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88")
	txTwoBedrockTransaction := newBedrockTx(
		0,
		to,
		big.NewInt(0),
		0,
		gasPrice,
		nil,
	)
	txTwoBedrockRPCTransaction := BedrockRPCTransaction{
		Tx: txTwoBedrockTransaction,
		TxExtraInfo: TxExtraInfo{
			BlockNumber: &blockNumberString,
			BlockHash:   &blockHash,
			From:        &to,
			TxHash:      &txTwoHash,
		},
	}

	// Execute the transaction trace
	mockTraceTransaction(ctx, testSuite, "testdata/goerli_bedrock_tx_trace_5003318_2.json")
	m, err = c.TraceTransactions(ctx, blockHash, []BedrockRPCTransaction{txTwoBedrockRPCTransaction})

	// Expect the result
	expectedCalls = constructTxTwoExpectedCalls(m, txTwoHash)
	testSuite.NoError(err)
	testSuite.Equal(len(m), 1)
	testSuite.Equal(23, len(m[txTwoHash.Hex()]))
	testSuite.Equal(expectedCalls, m[txTwoHash.Hex()])
}

func constructTxOneExpectedCalls(m map[string][]*FlatCall, txHash EthCommon.Hash) []*FlatCall {
	return []*FlatCall{
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("deaddeaddeaddeaddeaddeaddeaddeaddead0001"),
			To:           EthCommon.HexToAddress("4200000000000000000000000000000000000015"),
			Value:        m[txHash.Hex()][0].Value,
			GasUsed:      convertBigInt("0xb729"),
			Input:        "0x015d8eb900000000000000000000000000000000000000000000000000000000008097790000000000000000000000000000000000000000000000000000000063dd1a98000000000000000000000000000000000000000000000000000000000004ee2f1ed96835176d084c845bd2c09456d60401d74861b690bdabac97f6724f4b4bdf00000000000000000000000000000000000000000000000000000000000000020000000000000000000000007431310e026b69bfc676c0013e12a1a11411eec9000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "DELEGATECALL",
			From:         EthCommon.HexToAddress("4200000000000000000000000000000000000015"),
			To:           EthCommon.HexToAddress("c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d30015"),
			Value:        m[txHash.Hex()][1].Value,
			GasUsed:      convertBigInt("0x4a28"),
			Input:        "0x015d8eb900000000000000000000000000000000000000000000000000000000008097790000000000000000000000000000000000000000000000000000000063dd1a98000000000000000000000000000000000000000000000000000000000004ee2f1ed96835176d084c845bd2c09456d60401d74861b690bdabac97f6724f4b4bdf00000000000000000000000000000000000000000000000000000000000000020000000000000000000000007431310e026b69bfc676c0013e12a1a11411eec9000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240",
			Revert:       false,
			ErrorMessage: "",
		},
	}
}

func constructTxTwoExpectedCalls(m map[string][]*FlatCall, txTwoHash EthCommon.Hash) []*FlatCall {
	return []*FlatCall{
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("e261e28d9fccd3742629fef031e63327585b40f0"),
			To:           EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			Value:        m[txTwoHash.Hex()][0].Value,
			GasUsed:      convertBigInt("0x4a853"),
			Input:        "0xb1dc65a40001b9ada1cc34d3d18c4f9705f77b5036df2e9041c9b16c1e511d3dff17ab81000000000000000000000000000000000000000000000000000000000029a1030dabb9edf2d1abbfd18a5f5b5dd8f6fe9e3cac59160d012ad1ad2c312acb741700000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000062000000000000000000000000000000000000000000000000000000000000006a00101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000052000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000f43fc2c04ee00000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f000000000000000000000000000000000000000000000000000000000000a869000000000000000000000000000000000000000000000000000000073890e54a0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000a8690000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000000064000000000000000000000000620a71123c7090c9e66daea5235872b250f3c2610000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000030d400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e60cead5fcd752b6694f90a16af7a46e5b6df817000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000b9d5d9136855f6fec3c0993fee6e9ce8a2978466f4086b5b683bcade1f3f98b34e8b3d95c103324a5cd2762619d86b689222c9000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001cdc000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000397fce5bbf0a173bc6489b5d80dc6f25abe0583d301b3d49af106fb8b7c8b1cb45e601f60295cc3d24785ee8a9677d4a6adeba6bbc452ba9f23e5f06d85bdb936d65c22dc9ce5b03961de239adc29a90d2a8d91a92378bcdd9c684b317c9d78f100000000000000000000000000000000000000000000000000000000000000034474147f9f712b068497b1895ae6b62969d7d29b39a898708028aa6494c8a8eb1df987ff11c5069eed5ca8db0fa5b4ccce7bf7cd2be9a68988194366745e6cd337b633327318d96df91aa35e7330413955593139f40f4c630a179bdf8f03bc94",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("8b29d2f18c448835c45df5e3f6de004c27c9cc11"),
			Value:        m[txTwoHash.Hex()][1].Value,
			GasUsed:      convertBigInt("0x938"),
			Input:        "0x46f8e6d7",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("0af29c7539f767427aae2a1e212ae07d562f8f51"),
			Value:        m[txTwoHash.Hex()][2].Value,
			GasUsed:      convertBigInt("0x334b"),
			Input:        "0x9086658e00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f000000000000000000000000000000000000000000000000000000000000a869000000000000000000000000000000000000000000000000000000073890e54a",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("bcdc9f4cb4f864473ce1a6788c80f9860df013e8"),
			Value:        m[txTwoHash.Hex()][3].Value,
			GasUsed:      convertBigInt("0x1de8"),
			Input:        "0xe71e65ce00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016f4086b5b683bcade1f3f98b34e8b3d95c103324a5cd2762619d86b689222c9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("bcdc9f4cb4f864473ce1a6788c80f9860df013e8"),
			To:           EthCommon.HexToAddress("8b29d2f18c448835c45df5e3f6de004c27c9cc11"),
			Value:        m[txTwoHash.Hex()][4].Value,
			GasUsed:      convertBigInt("0x1d2"),
			Input:        "0xff888fb1247352d5fa3af29c281d02ee5602cce2d4f01d65d1684133d24ed7b9c5e92f42",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			Value:        m[txTwoHash.Hex()][5].Value,
			GasUsed:      convertBigInt("0x220da"),
			Input:        "0xabc39f1f00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a8690000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000000064000000000000000000000000620a71123c7090c9e66daea5235872b250f3c2610000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000030d400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e60cead5fcd752b6694f90a16af7a46e5b6df817000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000b9d5d9136855f6fec3c0993fee6e9ce8a2978466f4086b5b683bcade1f3f98b34e8b3d95c103324a5cd2762619d86b689222c9000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001cdc0000000000000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("e60cead5fcd752b6694f90a16af7a46e5b6df817"),
			Value:        m[txTwoHash.Hex()][7].Value,
			GasUsed:      convertBigInt("0x189"),
			Input:        "0x01ffc9a701ffc9a700000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("e60cead5fcd752b6694f90a16af7a46e5b6df817"),
			Value:        m[txTwoHash.Hex()][8].Value,
			GasUsed:      convertBigInt("0x189"),
			Input:        "0x01ffc9a7ffffffff00000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("e60cead5fcd752b6694f90a16af7a46e5b6df817"),
			Value:        big.NewInt(0),
			GasUsed:      convertBigInt("0x178"),
			Input:        "0x01ffc9a73015b91c00000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("473fce1b02c4b95d20ebe0f8840b10a9426b7c8b"),
			Value:        m[txTwoHash.Hex()][10].Value,
			GasUsed:      convertBigInt("0x1f0bb"),
			Input:        "0x004b61bb000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030d40000000000000000000000000e60cead5fcd752b6694f90a16af7a46e5b6df817000000000000000000000000000000000000000000000000000000000000a869000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000620a71123c7090c9e66daea5235872b250f3c26100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001cdc0000000000000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("473fce1b02c4b95d20ebe0f8840b10a9426b7c8b"),
			To:           EthCommon.HexToAddress("e60cead5fcd752b6694f90a16af7a46e5b6df817"),
			Value:        m[txTwoHash.Hex()][11].Value,
			GasUsed:      convertBigInt("0x1df31"),
			Input:        "0x3015b91c0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000a869000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000620a71123c7090c9e66daea5235872b250f3c26100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001cdc0000000000000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("e60cead5fcd752b6694f90a16af7a46e5b6df817"),
			To:           EthCommon.HexToAddress("473fce1b02c4b95d20ebe0f8840b10a9426b7c8b"),
			Value:        m[txTwoHash.Hex()][11].Value,
			GasUsed:      convertBigInt("0x1b04e"),
			Input:        "0x96f4e9f9000000000000000000000000000000000000000000000000000000000000a869000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f00000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000620a71123c7090c9e66daea5235872b250f3c26100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001cdd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004497a657c90000000000000000000000000000000000000000000000000000000000030d40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("473fce1b02c4b95d20ebe0f8840b10a9426b7c8b"),
			To:           EthCommon.HexToAddress("6e532f86cd5721a976f15560aa0683521cfab7e7"),
			Value:        m[txTwoHash.Hex()][13].Value,
			GasUsed:      convertBigInt("0x2e86"),
			Input:        "0x38724a95000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f00000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000620a71123c7090c9e66daea5235872b250f3c26100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001cdd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004497a657c90000000000000000000000000000000000000000000000000000000000030d40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("6e532f86cd5721a976f15560aa0683521cfab7e7"),
			To:           EthCommon.HexToAddress("0af29c7539f767427aae2a1e212ae07d562f8f51"),
			Value:        big.NewInt(0),
			GasUsed:      convertBigInt("0x3f9"),
			Input:        "0x8e160ef4000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f000000000000000000000000000000000000000000000000000000000000a869",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("473fce1b02c4b95d20ebe0f8840b10a9426b7c8b"),
			To:           EthCommon.HexToAddress("dc2cc710e42857672e7907cf474a69b63b93089f"),
			Value:        m[txTwoHash.Hex()][14].Value,
			GasUsed:      convertBigInt("0x929c"),
			Input:        "0x23b872dd000000000000000000000000e60cead5fcd752b6694f90a16af7a46e5b6df8170000000000000000000000006e532f86cd5721a976f15560aa0683521cfab7e70000000000000000000000000000000000000000000000000000000000000064",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("473fce1b02c4b95d20ebe0f8840b10a9426b7c8b"),
			To:           EthCommon.HexToAddress("6e532f86cd5721a976f15560aa0683521cfab7e7"),
			Value:        m[txTwoHash.Hex()][15].Value,
			GasUsed:      convertBigInt("0xb45f"),
			Input:        "0xa7d3e02f00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000064000000000000000000000000e60cead5fcd752b6694f90a16af7a46e5b6df81700000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f00000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000620a71123c7090c9e66daea5235872b250f3c26100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001cdd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004497a657c90000000000000000000000000000000000000000000000000000000000030d40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("6e532f86cd5721a976f15560aa0683521cfab7e7"),
			To:           EthCommon.HexToAddress("8b29d2f18c448835c45df5e3f6de004c27c9cc11"),
			Value:        m[txTwoHash.Hex()][16].Value,
			GasUsed:      convertBigInt("0x168"),
			Input:        "0x46f8e6d7",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("6e532f86cd5721a976f15560aa0683521cfab7e7"),
			To:           EthCommon.HexToAddress("dc2cc710e42857672e7907cf474a69b63b93089f"),
			Value:        m[txTwoHash.Hex()][17].Value,
			GasUsed:      convertBigInt("0x1fbf"),
			Input:        "0xa9059cbb00000000000000000000000025c53f77e4f6fc85cba2a892ac62a44c770389cc0000000000000000000000000000000000000000000000000000000000000064",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("25c53f77e4f6fc85cba2a892ac62a44c770389cc"),
			Value:        m[txTwoHash.Hex()][18].Value,
			GasUsed:      convertBigInt("0x47c2"),
			Input:        "0xea6192a2000000000000000000000000794c23bb0a718f4a79ee96531d40c54a67f7f0370000000000000000000000000000000000000000000000000000000000000064",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "CALL",
			From:         EthCommon.HexToAddress("25c53f77e4f6fc85cba2a892ac62a44c770389cc"),
			To:           EthCommon.HexToAddress("dc2cc710e42857672e7907cf474a69b63b93089f"),
			Value:        m[txTwoHash.Hex()][19].Value,
			GasUsed:      convertBigInt("0x1fbf"),
			Input:        "0xa9059cbb000000000000000000000000794c23bb0a718f4a79ee96531d40c54a67f7f0370000000000000000000000000000000000000000000000000000000000000064",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("0000000000000000000000000000000000000001"),
			Value:        m[txTwoHash.Hex()][20].Value,
			GasUsed:      convertBigInt("0xbb8"),
			Input:        "0x63b1bbbb4fbf39ff1d3e4026353f38907d8656ea9cf5f77a2af3f0316fcbbe56000000000000000000000000000000000000000000000000000000000000001c97fce5bbf0a173bc6489b5d80dc6f25abe0583d301b3d49af106fb8b7c8b1cb44474147f9f712b068497b1895ae6b62969d7d29b39a898708028aa6494c8a8eb",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("0000000000000000000000000000000000000001"),
			Value:        m[txTwoHash.Hex()][21].Value,
			GasUsed:      convertBigInt("0xbb8"),
			Input:        "0x63b1bbbb4fbf39ff1d3e4026353f38907d8656ea9cf5f77a2af3f0316fcbbe56000000000000000000000000000000000000000000000000000000000000001c5e601f60295cc3d24785ee8a9677d4a6adeba6bbc452ba9f23e5f06d85bdb9361df987ff11c5069eed5ca8db0fa5b4ccce7bf7cd2be9a68988194366745e6cd3",
			Revert:       false,
			ErrorMessage: "",
		},
		{
			Type:         "STATICCALL",
			From:         EthCommon.HexToAddress("794c23bb0a718f4a79ee96531d40c54a67f7f037"),
			To:           EthCommon.HexToAddress("0000000000000000000000000000000000000001"),
			Value:        m[txTwoHash.Hex()][22].Value,
			GasUsed:      convertBigInt("0xbb8"),
			Input:        "0x63b1bbbb4fbf39ff1d3e4026353f38907d8656ea9cf5f77a2af3f0316fcbbe56000000000000000000000000000000000000000000000000000000000000001bd65c22dc9ce5b03961de239adc29a90d2a8d91a92378bcdd9c684b317c9d78f137b633327318d96df91aa35e7330413955593139f40f4c630a179bdf8f03bc94",
			Revert:       false,
			ErrorMessage: "",
		},
	}
}
