package optimism

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/core/types"
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

	var convertBigInt = func(s string) *big.Int {
		i, _ := new(big.Int).SetString(s, 0)
		return i
	}

	var correctHeader *EthTypes.Header
	var correctBlock *rpcBedrockBlock
	testSuite.NoError(json.Unmarshal(file, &correctHeader))
	testSuite.NoError(json.Unmarshal(file, &correctBlock))
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
	testSuite.Equal(expectedHeader, correctHeader)
	expectedBlockHash := EthCommon.HexToHash("0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774")
	testSuite.Equal(expectedBlockHash, correctBlock.Hash)

	// Fetch the latest block
	header, block, err := c.getBedrockBlock(
		ctx,
		"eth_getBlockByNumber",
		"latest",
		true,
	)
	testSuite.Equal(correctBlock, block)
	testSuite.Equal(correctHeader, header)
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
	testSuite.T().Skip()

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
	).Once()

	tx1 := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	tx2 := EthCommon.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88")

	// mockDebugTraceTransaction(ctx, testSuite, tx1, "testdata/goerli_bedrock_tx_5003318_1.json")
	// mockDebugTraceTransaction(ctx, testSuite, tx2, "testdata/goerli_bedrock_tx_5003318_2.json")
	mockDebugTraceBedrockBlock(ctx, testSuite, tx1, "testdata/goerli_bedrock_block_trace_5003318.json")
	mockGetTransactionReceipt(ctx, testSuite, []EthCommon.Hash{tx1, tx2}, []string{"testdata/goerli_bedrock_tx_receipt_5003318_1.json", "testdata/goerli_bedrock_tx_receipt_5003318_2.json"})

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
	testSuite.Equal(correct.Block, resp)
}

//nolint:unused
func mockDebugTraceTransaction(ctx context.Context, testSuite *ClientBedrockTestSuite, txhash EthCommon.Hash, txFileData string) {
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "debug_traceTransaction"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 1)
			testSuite.Len(r[0].Args, 2)
			testSuite.Equal(
				txhash.Hex(),
				r[0].Args[0],
			)
			testSuite.Equal(testBedrockTraceConfig, r[0].Args[1])

			file, err := os.ReadFile(txFileData)
			testSuite.NoError(err)

			call := new(Call)
			testSuite.NoError(call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
}

//nolint:unused
func mockGetTransactionReceipt(ctx context.Context, testSuite *ClientBedrockTestSuite, txhashes []EthCommon.Hash, txFileData []string) {
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

				receipt := new(types.Receipt)
				testSuite.NoError(receipt.UnmarshalJSON(file))
				*(r[0].Result.(**types.Receipt)) = receipt
			}
		},
	).Once()
}
