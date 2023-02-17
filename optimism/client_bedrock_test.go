package optimism

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/eth"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
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

var convertBigInt = func(s string) *big.Int {
	i, _ := new(big.Int).SetString(s, 0)
	return i
}

type ClientBedrockTestSuite struct {
	suite.Suite

	mockJSONRPC         *mocks.JSONRPC
	mockGraphQL         *mocks.GraphQL
	mockCurrencyFetcher *mocks.CurrencyFetcher
}

func TestClientBedrock(t *testing.T) {
	suite.Run(t, new(ClientBedrockTestSuite))
}

func (testSuite *ClientBedrockTestSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
	testSuite.mockCurrencyFetcher = &mocks.CurrencyFetcher{}
}

// TestIsPreBedrock tests the [IsPreBedrock] function.
func (testSuite *ClientBedrockTestSuite) TestIsPreBedrock() {
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
	testSuite.True(c.IsPreBedrock(big.NewInt(5_003_317)))
	testSuite.False(c.IsPreBedrock(big.NewInt(5_003_318)))
}

// TestIsPreBedrockNil tests the [IsPreBedrock] function.
func (testSuite *ClientBedrockTestSuite) TestIsPreBedrockNil() {
	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		tc:              testBedrockTraceConfig,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
		filterTokens:    false,
		// We don't set the bedrock block here to revert to pre-bedrock block behavior if unset.
		// bedrockBlock:    big.NewInt(5_003_318),
	}
	testSuite.True(c.IsPreBedrock(big.NewInt(0)))
	testSuite.True(c.IsPreBedrock(big.NewInt(5_003_317)))
	testSuite.True(c.IsPreBedrock(big.NewInt(5_003_318)))
}

func (testSuite *ClientBedrockTestSuite) TestGetBedrockBlock() {
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

	file, err := os.ReadFile("testdata/goerli_bedrock_block_5003318.json")
	testSuite.NoError(err)

	ctx := context.Background()
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			*r = json.RawMessage(file)
		},
	).Once()
	testSuite.mockCurrencyFetcher.On(
		"FetchCurrency",
		ctx,
		uint64(5003318),
		mock.Anything,
	).Return(
		&RosettaTypes.Currency{
			Symbol:   "LINK",
			Decimals: 18,
			Metadata: map[string]interface{}{"token_address": "0xdc2CC710e42857672E7907CF474a69B63B93089f"}},
		nil,
	).Once()

	var correctHeader *EthTypes.Header
	testSuite.NoError(json.Unmarshal(file, &correctHeader))
	// var correctBlock *rpcBedrockBlock
	// testSuite.NoError(json.Unmarshal(file, &correctBlock))
	expectedHeader := &EthTypes.Header{
		ParentHash:  EthCommon.HexToHash("0x70a4f8a536e03c2bb46ceafeafabe4070c3ecf56039c70bc0b4a5584684f664a"),
		UncleHash:   EthCommon.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    EthCommon.HexToAddress("0x4200000000000000000000000000000000000011"),
		Root:        EthCommon.HexToHash("0x64fc9af5be01af062cfd137cf1f2cfd78dd28dac15b499b227fb0e7183da4769"),
		TxHash:      EthCommon.HexToHash("0xada45aa72d8206747ec7a2dcbaed701b921389ca9b8275a516e6fac044f23357"),
		ReceiptHash: EthCommon.HexToHash("0x7be5f73e807a2564853738e784008e499fd8498ce803d8c0b3a814c996840105"),
		Bloom:       EthTypes.BytesToBloom(EthCommon.FromHex("0x000000000000000000000003001000000001100000002000000002000000001002108040000000000000020000000000000000000204000400000000002000080040210000000000000080084000000000000040000100000008000000000000100020000000002000000000200009000000000000000000000000100000002000204000080000000000000008000008000100000000a2000800020000000000020000000000000000000000000000000400000000000000408000000000000004000002000000000000000000024800000000000000004010010001000000000010200000005000008000040000000000000000000000000000000800800000")),
		Difficulty:  correctHeader.Difficulty,
		Number:      convertBigInt("0x4c5836"),
		GasLimit:    convertBigInt("0x17d7840").Uint64(),
		GasUsed:     convertBigInt("0x4a853").Uint64(),
		Time:        convertBigInt("0x63dd1ad0").Uint64(),
		Extra:       []byte{},
		MixDigest:   EthCommon.HexToHash("0x11bca9946ac51ed6451e9182f41b3513d27839aad5e102aead7b1f7f5f55bbdf"),
		Nonce:       EthTypes.BlockNonce{},
		BaseFee:     big.NewInt(49),
	}
	expectedBlockHash := EthCommon.HexToHash("0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774")

	expectedBlockNumber := "0x4c5836"
	expectedTransactionFrom1 := EthCommon.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddead0001")
	expectedTransactionFrom2 := EthCommon.HexToAddress("0xe261e28d9fccd3742629fef031e63327585b40f0")
	expectedTxHash1 := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	expectedTxHash2 := EthCommon.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88")
	expectedBlockTransactions := []BedrockRPCTransaction{
		{
			Tx: NewTransactionFromFields(
				convertBigInt("0x7e").Uint64(),
				0,
				nil,
				nil,
				nil,
				convertBigInt("0x8f0d180").Uint64(),
				convertBigInt("0x0"),
				EthCommon.Hex2Bytes("0x015d8eb900000000000000000000000000000000000000000000000000000000008097790000000000000000000000000000000000000000000000000000000063dd1a98000000000000000000000000000000000000000000000000000000000004ee2f1ed96835176d084c845bd2c09456d60401d74861b690bdabac97f6724f4b4bdf00000000000000000000000000000000000000000000000000000000000000020000000000000000000000007431310e026b69bfc676c0013e12a1a11411eec9000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240"),
				nil,
				nil,
				nil,
				EthCommon.HexToAddress("0x4200000000000000000000000000000000000015"),
				nil,
				EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611"),
			),
			TxExtraInfo: TxExtraInfo{
				BlockNumber: &expectedBlockNumber,
				BlockHash:   &expectedBlockHash,
				From:        &expectedTransactionFrom1,
				TxHash:      &expectedTxHash1,
			},
		},
		{
			Tx: NewTransactionFromFields(
				convertBigInt("0x2").Uint64(),
				convertBigInt("0x1fc9").Uint64(),
				convertBigInt("0xb2d05e61"),
				convertBigInt("0xb2d05e30"),
				convertBigInt("0xb2d05e7e"),
				convertBigInt("0x5b8d80").Uint64(),
				convertBigInt("0x0"),
				EthCommon.Hex2Bytes("0xb1dc65a40001b9ada1cc34d3d18c4f9705f77b5036df2e9041c9b16c1e511d3dff17ab81000000000000000000000000000000000000000000000000000000000029a1030dabb9edf2d1abbfd18a5f5b5dd8f6fe9e3cac59160d012ad1ad2c312acb741700000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000062000000000000000000000000000000000000000000000000000000000000006a00101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000052000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000f43fc2c04ee00000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f000000000000000000000000000000000000000000000000000000000000a869000000000000000000000000000000000000000000000000000000073890e54a0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000a8690000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000000064000000000000000000000000620a71123c7090c9e66daea5235872b250f3c2610000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000030d400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e60cead5fcd752b6694f90a16af7a46e5b6df817000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000b9d5d9136855f6fec3c0993fee6e9ce8a2978466f4086b5b683bcade1f3f98b34e8b3d95c103324a5cd2762619d86b689222c9000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001cdc000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000397fce5bbf0a173bc6489b5d80dc6f25abe0583d301b3d49af106fb8b7c8b1cb45e601f60295cc3d24785ee8a9677d4a6adeba6bbc452ba9f23e5f06d85bdb936d65c22dc9ce5b03961de239adc29a90d2a8d91a92378bcdd9c684b317c9d78f100000000000000000000000000000000000000000000000000000000000000034474147f9f712b068497b1895ae6b62969d7d29b39a898708028aa6494c8a8eb1df987ff11c5069eed5ca8db0fa5b4ccce7bf7cd2be9a68988194366745e6cd337b633327318d96df91aa35e7330413955593139f40f4c630a179bdf8f03bc94"),
				convertBigInt("0x1"),
				convertBigInt("0xf251114b84dbab64fb9629e2298252b09077080169dd3970b7ac06bd73be5a73"),
				convertBigInt("0x7a7481ae00acfa76673656a93b538d1be1bc7b4ecd16204e8e80cc369b2fd63c"),
				EthCommon.HexToAddress("0x794c23bb0a718f4a79ee96531d40c54a67f7f037"),
				convertBigInt("0x1a4"),
				EthCommon.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88"),
			),
			TxExtraInfo: TxExtraInfo{
				BlockNumber: &expectedBlockNumber,
				BlockHash:   &expectedBlockHash,
				From:        &expectedTransactionFrom2,
				TxHash:      &expectedTxHash2,
			},
		},
	}
	expectedUncles := []EthCommon.Hash{}
	expectedBlock := NewRpcBedrockBlock(
		expectedBlockHash,
		expectedBlockTransactions,
		expectedUncles,
	)

	// Fetch the latest block
	header, block, err := c.getBedrockBlock(
		ctx,
		"eth_getBlockByNumber",
		"latest",
		true,
	)
	testSuite.Equal(expectedBlock.Hash, block.Hash)
	testSuite.Equal(expectedBlock.UncleHashes, block.UncleHashes)
	testSuite.Equal(len(expectedBlock.Transactions), len(block.Transactions))
	testSuite.Equal(expectedHeader, header)
	testSuite.NoError(err)
}

func (testSuite *ClientBedrockTestSuite) TestTraceBlockByHash() {
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
	myTx := NewBedrockTransaction(
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

	// Mock the block trace
	mockDebugTraceBedrockBlock(ctx, testSuite, tx1, "testdata/goerli_bedrock_block_trace_5003318.json")

	// Call
	blkHash := EthCommon.HexToHash("0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774")
	m, err := c.TraceBlockByHash(ctx, blkHash, txs)
	testSuite.NoError(err)

	testSuite.Equal(len(m), 2)
	testSuite.NotNil(m[tx1.Hex()])
}

//nolint:unused
func mockDebugTraceBedrockBlock(ctx context.Context, testSuite *ClientBedrockTestSuite, txhash EthCommon.Hash, txFileData string) {
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

func (testSuite *ClientBedrockTestSuite) TestBedrockBlockCurrent() {
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

	ctx := context.Background()
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/goerli_bedrock_block_5003318.json")
			testSuite.NoError(err)

			*r = json.RawMessage(file)
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		[]interface{}{"latest", true},
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/goerli_bedrock_block_5003318.json")
			testSuite.NoError(err)

			*r = json.RawMessage(file)
		},
	).Once()
	testSuite.mockCurrencyFetcher.On(
		"FetchCurrency",
		ctx,
		uint64(5003318),
		mock.Anything,
	).Return(
		&RosettaTypes.Currency{
			Symbol:   "LINK",
			Decimals: 18,
			Metadata: map[string]interface{}{"token_address": "0xdc2CC710e42857672E7907CF474a69B63B93089f"}},
		nil,
	)

	tx1 := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	tx2 := EthCommon.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88")

	mockDebugTraceBedrockBlock(ctx, testSuite, tx1, "testdata/goerli_bedrock_block_trace_5003318.json")
	mockGetBedrockTransactionReceipt(ctx, testSuite, []EthCommon.Hash{tx1, tx2}, []string{"testdata/goerli_bedrock_tx_receipt_5003318_1.json", "testdata/goerli_bedrock_tx_receipt_5003318_2.json"})

	correctRaw, err := os.ReadFile("testdata/goerli_bedrock_block_response_5003318.json")
	testSuite.NoError(err)
	var correct *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correct))

	// Fetch the latest block
	resp, err := c.Block(
		ctx,
		nil,
	)
	testSuite.NoError(err)
	// Check the block identifier
	expectedBlockIndex := int64(5003318)
	expectedBlockHash := "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774"
	testSuite.Equal(expectedBlockHash, resp.BlockIdentifier.Hash)
	testSuite.Equal(expectedBlockIndex, resp.BlockIdentifier.Index)
	// Check the parent block identifier
	expectedParentBlockIndex := int64(5003317)
	expectedParentBlockHash := "0x70a4f8a536e03c2bb46ceafeafabe4070c3ecf56039c70bc0b4a5584684f664a"
	testSuite.Equal(expectedParentBlockHash, resp.ParentBlockIdentifier.Hash)
	testSuite.Equal(expectedParentBlockIndex, resp.ParentBlockIdentifier.Index)
	// Transactions
	testSuite.Equal(2, len(resp.Transactions))
	expectedFirstOperations := []*RosettaTypes.Operation{}
	expectedFirstRosettaTx := RosettaTypes.Transaction{
		TransactionIdentifier: &RosettaTypes.TransactionIdentifier{
			Hash: "0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611",
		},
		Operations:          expectedFirstOperations,
		RelatedTransactions: nil,
		Metadata: map[string]interface{}{
			"gas_limit": "0x8f0d180",
			"gas_price": "0x0",
			"receipt": map[string]interface{}{
				"GasPrice":   float64(0),
				"GasUsed":    float64(0),
				"Logs":       []interface{}{},
				"RawMessage": nil, // This is just the serialized raw tx object - we can ignore
			},
			"trace": []map[string]interface{}(nil),
		},
	}
	testSuite.Equal(expectedFirstRosettaTx.TransactionIdentifier, resp.Transactions[0].TransactionIdentifier)
	testSuite.Equal(expectedFirstRosettaTx.Operations, resp.Transactions[0].Operations)
	testSuite.Equal(expectedFirstRosettaTx.RelatedTransactions, resp.Transactions[0].RelatedTransactions)
	testSuite.Equal(expectedFirstRosettaTx.Metadata["gas_limit"], resp.Transactions[0].Metadata["gas_limit"])
	testSuite.Equal(expectedFirstRosettaTx.Metadata["gas_price"], resp.Transactions[0].Metadata["gas_price"])
	testSuite.Equal(expectedFirstRosettaTx.Metadata["trace"], resp.Transactions[0].Metadata["trace"])
	testSuite.Equal(
		(expectedFirstRosettaTx.Metadata["receipt"]).(map[string]interface{})["GasPrice"],
		resp.Transactions[0].Metadata["receipt"].(map[string]interface{})["GasPrice"],
	)
	testSuite.Equal(
		(expectedFirstRosettaTx.Metadata["receipt"]).(map[string]interface{})["GasUsed"],
		resp.Transactions[0].Metadata["receipt"].(map[string]interface{})["GasUsed"],
	)
	testSuite.Equal(
		(expectedFirstRosettaTx.Metadata["receipt"]).(map[string]interface{})["Logs"],
		resp.Transactions[0].Metadata["receipt"].(map[string]interface{})["Logs"],
	)
	// Ignore raw message
	// testSuite.Equal(
	// 	(expectedFirstRosettaTx.Metadata["receipt"]).(map[string]interface{})["RawMessage"],
	// 	resp.Transactions[0].Metadata["receipt"].(map[string]interface{})["RawMessage"],
	// )
	expectedSecondOperations := []*RosettaTypes.Operation{}
	expectedSecondRosettaTx := RosettaTypes.Transaction{
		TransactionIdentifier: &RosettaTypes.TransactionIdentifier{
			Hash: "0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88",
		},
		Operations:          expectedSecondOperations,
		RelatedTransactions: nil,
		Metadata: map[string]interface{}{
			"gas_limit": "0x5b8d80",
			"gas_price": "0xb2d05e61",
			"receipt": map[string]interface{}{
				"GasPrice":   float64(convertBigInt("0xb2d05e30").Int64()),
				"GasUsed":    float64(convertBigInt("0xb2d05e30").Int64()),
				"Logs":       []interface{}{},
				"RawMessage": nil, // This is just the serialized raw tx object - we can ignore
			},
			"trace": []map[string]interface{}(nil),
		},
	}
	testSuite.Equal(expectedSecondRosettaTx.TransactionIdentifier, resp.Transactions[1].TransactionIdentifier)
	// Check operations
	testSuite.Equal(6, len(resp.Transactions[1].Operations))
	// The first operation should be an erc20 transfer
	testSuite.Equal(
		&RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 0,
			},
			Status: RosettaTypes.String(SuccessStatus),
			Type:   ERC20TransferOpType,
			Amount: &RosettaTypes.Amount{
				Value: "100",
				Currency: &RosettaTypes.Currency{
					Symbol:   "LINK",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": "0xdc2CC710e42857672E7907CF474a69B63B93089f",
					},
				},
			},
			Account: &RosettaTypes.AccountIdentifier{
				Address: "0xE60CeAd5FCD752B6694f90a16af7a46e5b6Df817",
			},
		},
		resp.Transactions[1].Operations[0],
	)
	testSuite.Equal(
		&RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 1,
			},
			RelatedOperations: []*RosettaTypes.OperationIdentifier{
				{
					Index: 0,
				},
			},
			Status: RosettaTypes.String(SuccessStatus),
			Type:   ERC20TransferOpType,
			Amount: &RosettaTypes.Amount{
				Value: "100",
				Currency: &RosettaTypes.Currency{
					Symbol:   "LINK",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": "0xdc2CC710e42857672E7907CF474a69B63B93089f",
					},
				},
			},
			Account: &RosettaTypes.AccountIdentifier{
				Address: "0x6E532F86CD5721A976f15560Aa0683521cFaB7e7",
			},
		},
		resp.Transactions[1].Operations[1],
	)
	testSuite.Equal(
		&RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 2,
			},
			Status: RosettaTypes.String(SuccessStatus),
			Type:   ERC20TransferOpType,
			Amount: &RosettaTypes.Amount{
				Value: "100",
				Currency: &RosettaTypes.Currency{
					Symbol:   "LINK",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": "0xdc2CC710e42857672E7907CF474a69B63B93089f",
					},
				},
			},
			Account: &RosettaTypes.AccountIdentifier{
				Address: "0x6E532F86CD5721A976f15560Aa0683521cFaB7e7",
			},
		},
		resp.Transactions[1].Operations[2],
	)
	testSuite.Equal(
		&RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 3,
			},
			RelatedOperations: []*RosettaTypes.OperationIdentifier{
				{
					Index: 2,
				},
			},
			Status: RosettaTypes.String(SuccessStatus),
			Type:   ERC20TransferOpType,
			Amount: &RosettaTypes.Amount{
				Value: "100",
				Currency: &RosettaTypes.Currency{
					Symbol:   "LINK",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": "0xdc2CC710e42857672E7907CF474a69B63B93089f",
					},
				},
			},
			Account: &RosettaTypes.AccountIdentifier{
				Address: "0x25c53f77e4f6FC85CbA2a892Ac62A44C770389cC",
			},
		},
		resp.Transactions[1].Operations[3],
	)
	testSuite.Equal(
		&RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 4,
			},
			Status: RosettaTypes.String(SuccessStatus),
			Type:   ERC20TransferOpType,
			Amount: &RosettaTypes.Amount{
				Value: "100",
				Currency: &RosettaTypes.Currency{
					Symbol:   "LINK",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": "0xdc2CC710e42857672E7907CF474a69B63B93089f",
					},
				},
			},
			Account: &RosettaTypes.AccountIdentifier{
				Address: "0x25c53f77e4f6FC85CbA2a892Ac62A44C770389cC",
			},
		},
		resp.Transactions[1].Operations[4],
	)
	testSuite.Equal(
		&RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 5,
			},
			RelatedOperations: []*RosettaTypes.OperationIdentifier{
				{
					Index: 4,
				},
			},
			Status: RosettaTypes.String(SuccessStatus),
			Type:   ERC20TransferOpType,
			Amount: &RosettaTypes.Amount{
				Value: "100",
				Currency: &RosettaTypes.Currency{
					Symbol:   "LINK",
					Decimals: 18,
					Metadata: map[string]interface{}{
						"token_address": "0xdc2CC710e42857672E7907CF474a69B63B93089f",
					},
				},
			},
			Account: &RosettaTypes.AccountIdentifier{
				Address: "0x794C23BB0a718F4a79eE96531d40C54A67f7f037",
			},
		},
		resp.Transactions[1].Operations[5],
	)

	// Check other transaction fields
	testSuite.Equal(expectedSecondRosettaTx.RelatedTransactions, resp.Transactions[1].RelatedTransactions)
	testSuite.Equal(expectedSecondRosettaTx.Metadata["gas_limit"], resp.Transactions[1].Metadata["gas_limit"])
	testSuite.Equal(expectedSecondRosettaTx.Metadata["gas_price"], resp.Transactions[1].Metadata["gas_price"])
	testSuite.Equal(expectedSecondRosettaTx.Metadata["trace"], resp.Transactions[1].Metadata["trace"])
	testSuite.Equal(
		(expectedSecondRosettaTx.Metadata["receipt"]).(map[string]interface{})["GasPrice"],
		resp.Transactions[1].Metadata["receipt"].(map[string]interface{})["GasPrice"],
	)
	// TODO: Assert gas used
	// testSuite.Equal(
	// 	(expectedSecondRosettaTx.Metadata["receipt"]).(map[string]interface{})["GasUsed"],
	// 	resp.Transactions[1].Metadata["receipt"].(map[string]interface{})["GasUsed"],
	// )
	// Ignore logs
	// testSuite.Equal(
	// 	(expectedSecondRosettaTx.Metadata["receipt"]).(map[string]interface{})["Logs"],
	// 	resp.Transactions[1].Metadata["receipt"].(map[string]interface{})["Logs"],
	// )
	// Ignore raw message
	// testSuite.Equal(
	// 	(expectedFirstRosettaTx.Metadata["receipt"]).(map[string]interface{})["RawMessage"],
	// 	resp.Transactions[1].Metadata["receipt"].(map[string]interface{})["RawMessage"],
	// )
	// Other fields
	testSuite.Equal(convertTime(convertBigInt("0x63dd1ad0").Uint64()), resp.Timestamp)
	testSuite.Nil(resp.Metadata)
}

//nolint:unused
func mockGetBedrockTransactionReceipt(ctx context.Context, testSuite *ClientBedrockTestSuite, txhashes []EthCommon.Hash, txFileData []string) {
	testSuite.Equal(len(txhashes), len(txFileData))
	numReceipts := len(txhashes)
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == numReceipts && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, numReceipts)
			for i := range txhashes {
				testSuite.Equal(
					txhashes[i].Hex(),
					r[i].Args[0],
				)

				file, err := os.ReadFile(txFileData[i])
				testSuite.NoError(err)

				receipt := new(EthTypes.Receipt)
				testSuite.NoError(receipt.UnmarshalJSON(file))
				*(r[i].Result.(**EthTypes.Receipt)) = receipt
			}
		},
	).Once()
}
