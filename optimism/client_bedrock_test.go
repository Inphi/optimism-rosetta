package optimism

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	EthCommon "github.com/ethereum/go-ethereum/common"
	EthHexutil "github.com/ethereum/go-ethereum/common/hexutil"
	EthTypes "github.com/ethereum/go-ethereum/core/types"

	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sync/semaphore"
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

func (testSuite *ClientBedrockTestSuite) TestParseBedrockBlock() {
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
	raw := json.RawMessage(file)

	ctx := context.Background()
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
	data := EthCommon.Hex2Bytes("0x015d8eb900000000000000000000000000000000000000000000000000000000008097790000000000000000000000000000000000000000000000000000000063dd1a98000000000000000000000000000000000000000000000000000000000004ee2f1ed96835176d084c845bd2c09456d60401d74861b690bdabac97f6724f4b4bdf00000000000000000000000000000000000000000000000000000000000000020000000000000000000000007431310e026b69bfc676c0013e12a1a11411eec9000000000000000000000000000000000000000000000000000000000000083400000000000000000000000000000000000000000000000000000000000f4240")
	data2 := EthCommon.Hex2Bytes("0xb1dc65a40001b9ada1cc34d3d18c4f9705f77b5036df2e9041c9b16c1e511d3dff17ab81000000000000000000000000000000000000000000000000000000000029a1030dabb9edf2d1abbfd18a5f5b5dd8f6fe9e3cac59160d012ad1ad2c312acb741700000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000062000000000000000000000000000000000000000000000000000000000000006a00101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000052000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000026000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000f43fc2c04ee00000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000dc2cc710e42857672e7907cf474a69b63b93089f000000000000000000000000000000000000000000000000000000000000a869000000000000000000000000000000000000000000000000000000073890e54a0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000a8690000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000000064000000000000000000000000620a71123c7090c9e66daea5235872b250f3c2610000000000000000000000000000000000000000000000000000000000000e6e0000000000000000000000000000000000000000000000000000000000030d400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e60cead5fcd752b6694f90a16af7a46e5b6df817000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000b9d5d9136855f6fec3c0993fee6e9ce8a2978466f4086b5b683bcade1f3f98b34e8b3d95c103324a5cd2762619d86b689222c9000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000001cdc000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000397fce5bbf0a173bc6489b5d80dc6f25abe0583d301b3d49af106fb8b7c8b1cb45e601f60295cc3d24785ee8a9677d4a6adeba6bbc452ba9f23e5f06d85bdb936d65c22dc9ce5b03961de239adc29a90d2a8d91a92378bcdd9c684b317c9d78f100000000000000000000000000000000000000000000000000000000000000034474147f9f712b068497b1895ae6b62969d7d29b39a898708028aa6494c8a8eb1df987ff11c5069eed5ca8db0fa5b4ccce7bf7cd2be9a68988194366745e6cd337b633327318d96df91aa35e7330413955593139f40f4c630a179bdf8f03bc94")
	recipient := EthCommon.HexToAddress("0x4200000000000000000000000000000000000015")
	recipient2 := EthCommon.HexToAddress("0x794c23bb0a718f4a79ee96531d40c54a67f7f037")
	nonce := uint64(0)
	nonce2 := convertBigInt("0x1fc9").Uint64()
	expectedBlockTransactions := []BedrockRPCTransaction{
		{
			Tx: &transaction{
				Type:                 (EthHexutil.Uint64)(convertBigInt("0x7e").Uint64()),
				Nonce:                (*EthHexutil.Uint64)(&nonce),
				Price:                (*EthHexutil.Big)(nil),
				MaxPriorityFeePerGas: (*EthHexutil.Big)(nil),
				MaxFeePerGas:         (*EthHexutil.Big)(nil),
				GasLimit:             (EthHexutil.Uint64)(convertBigInt("0x8f0d180").Uint64()),
				Value:                (*EthHexutil.Big)(convertBigInt("0x0")),
				Data:                 (*EthHexutil.Bytes)(&data),
				V:                    (*EthHexutil.Big)(nil),
				R:                    (*EthHexutil.Big)(nil),
				S:                    (*EthHexutil.Big)(nil),
				Recipient:            &recipient,
				ChainID:              (*EthHexutil.Big)(nil),
				HashValue:            EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611"),
			},
			TxExtraInfo: TxExtraInfo{
				BlockNumber: &expectedBlockNumber,
				BlockHash:   &expectedBlockHash,
				From:        &expectedTransactionFrom1,
				TxHash:      &expectedTxHash1,
			},
		},
		{
			Tx: &transaction{
				Type:                 (EthHexutil.Uint64)(convertBigInt("0x2").Uint64()),
				Nonce:                (*EthHexutil.Uint64)(&nonce2),
				Price:                (*EthHexutil.Big)(convertBigInt("0xb2d05e61")),
				MaxPriorityFeePerGas: (*EthHexutil.Big)(convertBigInt("0xb2d05e30")),
				MaxFeePerGas:         (*EthHexutil.Big)(convertBigInt("0xb2d05e7e")),
				GasLimit:             (EthHexutil.Uint64)(convertBigInt("0x5b8d80").Uint64()),
				Value:                (*EthHexutil.Big)(convertBigInt("0x0")),
				Data:                 (*EthHexutil.Bytes)(&data2),
				V:                    (*EthHexutil.Big)(convertBigInt("0x1")),
				R:                    (*EthHexutil.Big)(convertBigInt("0xf251114b84dbab64fb9629e2298252b09077080169dd3970b7ac06bd73be5a73")),
				S:                    (*EthHexutil.Big)(convertBigInt("0x7a7481ae00acfa76673656a93b538d1be1bc7b4ecd16204e8e80cc369b2fd63c")),
				Recipient:            &recipient2,
				ChainID:              (*EthHexutil.Big)(convertBigInt("0x1a4")),
				HashValue:            EthCommon.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88"),
			},
			TxExtraInfo: TxExtraInfo{
				BlockNumber: &expectedBlockNumber,
				BlockHash:   &expectedBlockHash,
				From:        &expectedTransactionFrom2,
				TxHash:      &expectedTxHash2,
			},
		},
	}
	expectedUncles := []EthCommon.Hash{}
	expectedBlock := &rpcBedrockBlock{
		Hash:         expectedBlockHash,
		Transactions: expectedBlockTransactions,
		UncleHashes:  expectedUncles,
	}

	// Fetch the latest block
	header, block, err := c.parseBedrockBlock(&raw)
	testSuite.Equal(expectedBlock.Hash, block.Hash)
	testSuite.Equal(expectedBlock.UncleHashes, block.UncleHashes)
	testSuite.Equal(len(expectedBlock.Transactions), len(block.Transactions))
	testSuite.Equal(expectedHeader, header)
	testSuite.NoError(err)
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
			Metadata: map[string]interface{}{ContractAddressKey: "0xdc2CC710e42857672E7907CF474a69B63B93089f"}},
		nil,
	)

	tx1 := EthCommon.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	tx2 := EthCommon.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88")

	// Execute the transaction trace
	mockBedrockTraceTransaction(ctx, testSuite, "testdata/goerli_bedrock_tx_trace_5003318_1.json")
	mockBedrockTraceTransaction(ctx, testSuite, "testdata/goerli_bedrock_tx_trace_5003318_2.json")
	// mockDebugTraceBedrockBlock(ctx, testSuite, "testdata/goerli_bedrock_block_trace_5003318.json")
	mockGetBedrockTransactionReceipt(ctx, testSuite, []EthCommon.Hash{tx1, tx2}, []string{"testdata/goerli_bedrock_tx_receipt_5003318_1.json", "testdata/goerli_bedrock_tx_receipt_5003318_2.json"})

	correctRaw, err := os.ReadFile("testdata/goerli_bedrock_block_response_5003318.json")
	testSuite.NoError(err)
	var correct *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correct))

	// Fetch the latest block and validate
	resp, err := c.Block(
		ctx,
		nil,
	)
	testSuite.NoError(err)
	testSuite.Equal(correct.Block, resp)
}

func mockBedrockTraceTransaction(ctx context.Context, testSuite *ClientBedrockTestSuite, txFileData string) {
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
			file, err := os.ReadFile(txFileData)
			testSuite.NoError(err)

			call := new(Call)
			testSuite.NoError(call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
}

//nolint:unused
func mockDebugTraceBedrockBlock(ctx context.Context, testSuite *ClientBedrockTestSuite, txFileData string) {
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

				*(r[i].Result.(*json.RawMessage)) = json.RawMessage(file)
			}
		},
	).Once()
}
