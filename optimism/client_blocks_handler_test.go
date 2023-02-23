package optimism

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/core/types"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sync/semaphore"
)

// ClientBlocksHandlerTestSuite tests the pre-bedrock client blocks handler.
type ClientBlocksHandlerTestSuite struct {
	suite.Suite

	mockJSONRPC         *mocks.JSONRPC
	mockGraphQL         *mocks.GraphQL
	mockCurrencyFetcher *mocks.CurrencyFetcher
	client              *Client
}

// SetupTest configures the test suite.
func (testSuite *ClientBlocksHandlerTestSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
	testSuite.mockCurrencyFetcher = &mocks.CurrencyFetcher{}
	testSuite.client = &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		traceSemaphore:  semaphore.NewWeighted(100),
	}
	// This test suite is for the pre-bedrock client blocks handler.
	testSuite.True(testSuite.client.IsPreBedrock(testSuite.client.bedrockBlock))
}

// TestBlockHandlerSuite runs the ClientBlocksHandlerTestSuite.
func TestBlockHandlerSuite(t *testing.T) {
	suite.Run(t, new(ClientBlocksHandlerTestSuite))
}

func (testSuite *ClientBlocksHandlerTestSuite) TestBlock_ERC20Mint() {
	token := "0xf8b089026cad7ddd8cb8d79036a1ff1d4233d64a"
	supportedTokens := map[string]bool{
		token: true,
	}

	tc, err := testTraceConfig()
	testSuite.NoError(err)
	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		tc:              tc,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
		filterTokens:    true,
		supportedTokens: supportedTokens,
	}

	ctx := context.Background()
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x12f062",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_1241186.json")
			testSuite.NoError(err)

			*r = json.RawMessage(file)
		},
	).Once()
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
				common.HexToHash("0xd919fe87c4bc24f767d1b7a165266658d542af9e3f9bc11dd1a2d1f4695df009").Hex(),
				r[0].Args[0],
			)
			testSuite.Equal(tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_1241186.json",
			)
			testSuite.NoError(err)

			call := new(Call)
			testSuite.NoError(call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 1)
			testSuite.Equal(
				"0xd919fe87c4bc24f767d1b7a165266658d542af9e3f9bc11dd1a2d1f4695df009",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_0xd919fe87c4bc24f767d1b7a165266658d542af9e3f9bc11dd1a2d1f4695df009.json",
			) // nolint
			testSuite.NoError(err)

			receipt := new(types.Receipt)
			testSuite.NoError(receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()
	testSuite.mockCurrencyFetcher.On(
		"FetchCurrency",
		ctx,
		uint64(1241186),
		mock.Anything,
	).Return(
		&RosettaTypes.Currency{
			Symbol:   TokenSymbol,
			Decimals: TokenDecimals,
			Metadata: map[string]interface{}{"token_address": token}},
		nil,
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_1241186.json")
	testSuite.NoError(err)
	var correctResp *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(1241186),
		},
	)
	testSuite.NoError(err)

	// Ensure types match
	jsonResp, err := jsonifyBlock(resp)
	testSuite.NoError(err)
	testSuite.Equal(correctResp.Block, jsonResp)
}

func (testSuite *ClientBlocksHandlerTestSuite) TestBlock_1502839_OPCriticalBug() {
	cf, err := newERC20CurrencyFetcher(testSuite.mockJSONRPC)
	testSuite.NoError(err)

	tc, err := testTraceConfig()
	testSuite.NoError(err)
	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
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

			file, err := os.ReadFile("testdata/block_1502839.json")
			testSuite.NoError(err)

			*r = json.RawMessage(file)
		},
	).Once()
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
				common.HexToHash("0x3ff079ba4ea0745401e9661d623550d24c9412ea9ad578bfbb0d441dadcce9bc").Hex(),
				r[0].Args[0],
			)
			testSuite.Equal(tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_1502839.json",
			)
			testSuite.NoError(err)

			call := new(Call)
			testSuite.NoError(call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 1)
			testSuite.Equal(
				"0x3ff079ba4ea0745401e9661d623550d24c9412ea9ad578bfbb0d441dadcce9bc",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_0x3ff079ba4ea0745401e9661d623550d24c9412ea9ad578bfbb0d441dadcce9bc.json",
			)
			testSuite.NoError(err)

			receipt := new(types.Receipt)
			testSuite.NoError(receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_1502839.json")
	testSuite.NoError(err)
	var correct *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correct))

	resp, err := c.Block(
		ctx,
		nil,
	)
	testSuite.Equal(correct.Block, resp)
	testSuite.NoError(err)
}

func (testSuite *ClientBlocksHandlerTestSuite) TestBlockCurrent_TraceCache() {
	cf, err := newERC20CurrencyFetcher(testSuite.mockJSONRPC)
	testSuite.NoError(err)

	tc, err := testTraceConfig()
	testSuite.NoError(err)

	tspec := tracerSpec{TracerPath: "call_tracer.js"}
	traceCache, err := NewTraceCache(testSuite.mockJSONRPC, tspec, time.Second*120, 10)
	testSuite.NoError(err)

	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		traceCache:      traceCache,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
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

			file, err := os.ReadFile("testdata/block_1.json")
			testSuite.NoError(err)

			*r = json.RawMessage(file)
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"CallContext",
		mock.Anything,
		mock.Anything,
		"debug_traceTransaction",
		common.HexToHash("0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a").Hex(),
		tc,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			file, err := os.ReadFile(
				"testdata/tx_trace_1.json",
			)
			testSuite.NoError(err)

			call := new(Call)
			testSuite.NoError(call.UnmarshalJSON(file))
			r := args.Get(1).(*Call)
			*r = *call
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 1)
			testSuite.Equal(
				"0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_1.json",
			)
			testSuite.NoError(err)

			receipt := new(types.Receipt)
			testSuite.NoError(receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_1.json")
	testSuite.NoError(err)
	var correct *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correct))

	resp, err := c.Block(
		ctx,
		nil,
	)
	testSuite.Equal(correct.Block, resp)
	testSuite.NoError(err)
}

// Failed ERC20 transfer with no receipts
func (testSuite *ClientBlocksHandlerTestSuite) TestBlock_ERC20TransferFailed() {
	tc, err := testTraceConfig()
	testSuite.NoError(err)
	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		tc:              tc,
		p:               params.MainnetChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0xe3d23b",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := os.ReadFile("testdata/block_14930491.json")
			testSuite.NoError(err)
			*r = json.RawMessage(file)
		},
	).Once()
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
				common.HexToHash("0x5a1ec671315432cf8b6a67d95b857109fcafae277ae2c673db40b44ca8dd5c1b").Hex(),
				r[0].Args[0],
			)
			testSuite.Equal(tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_14930491.json",
			)
			testSuite.NoError(err)

			call := new(Call)
			testSuite.NoError(call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 1)
			testSuite.Equal(
				"0x5a1ec671315432cf8b6a67d95b857109fcafae277ae2c673db40b44ca8dd5c1b",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_0x5a1ec671315432cf8b6a67d95b857109fcafae277ae2c673db40b44ca8dd5c1b.json",
			)
			testSuite.NoError(err)

			receipt := new(types.Receipt)
			testSuite.NoError(receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	testSuite.mockCurrencyFetcher.On(
		"FetchCurrency",
		ctx,
		uint64(14930491),
		mock.Anything,
	).Return(
		&RosettaTypes.Currency{
			Symbol:   TokenSymbol,
			Decimals: TokenDecimals,
			Metadata: map[string]interface{}{"token_address": opTokenContractAddress.String()}},
		nil,
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_14930491.json")
	testSuite.NoError(err)
	var correctResp *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(14930491),
		},
	)
	testSuite.NoError(err)
	testSuite.Equal(correctResp.Block, resp)
}

func (testSuite *ClientBlocksHandlerTestSuite) TestBlock_GoerliNoFeeEnforcement() {
	cf, err := newERC20CurrencyFetcher(testSuite.mockJSONRPC)
	testSuite.NoError(err)

	tc, err := testTraceConfig()
	testSuite.NoError(err)
	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.MainnetChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}
	c.p.ChainID = big.NewInt(420) // hack to coerce goerli checks

	ctx := context.Background()
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x1",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_goerli_367675.json")
			testSuite.NoError(err)

			*r = json.RawMessage(file)
		},
	).Once()
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
				common.HexToHash("0x2992c7d87b09484c5940f7d649bd9957c629a43ac477473b655dbb07d8c742a5").Hex(),
				r[0].Args[0],
			)
			testSuite.Equal(tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_goerli_367675.json",
			)
			testSuite.NoError(err)

			call := new(Call)
			testSuite.NoError(call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 1)
			testSuite.Equal(
				"0x2992c7d87b09484c5940f7d649bd9957c629a43ac477473b655dbb07d8c742a5",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_goerli_367675.json",
			)
			testSuite.NoError(err)

			receipt := new(types.Receipt)
			testSuite.NoError(receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_goerli_367675.json")
	testSuite.NoError(err)
	var correctResp *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(1),
		},
	)
	testSuite.Equal(correctResp.Block, resp)
	testSuite.NoError(err)
}

// Asserts "buggy" OVM behavior when destroying an account with itself as the recipient
func (testSuite *ClientBlocksHandlerTestSuite) TestBlock_OVMSelfDestruct() {
	cf, err := newERC20CurrencyFetcher(testSuite.mockJSONRPC)
	testSuite.NoError(err)

	tc, err := testTraceConfig()
	testSuite.NoError(err)
	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: cf,
		tc:              tc,
		p:               params.MainnetChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
	}

	ctx := context.Background()
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"0x1d24c0",
		true,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_1909952.json")
			testSuite.NoError(err)

			*r = json.RawMessage(file)
		},
	).Once()
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
				common.HexToHash("0xfa6db346b928db4c98ebf72a14ac52d0c884e2cfa70cf40816542c9d7d1caf13").Hex(),
				r[0].Args[0],
			)
			testSuite.Equal(tc, r[0].Args[1])

			file, err := os.ReadFile(
				"testdata/tx_trace_1909952.json",
			)
			testSuite.NoError(err)

			call := new(Call)
			testSuite.NoError(call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 1 && rpcs[0].Method == "eth_getTransactionReceipt"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 1)
			testSuite.Equal(
				"0xfa6db346b928db4c98ebf72a14ac52d0c884e2cfa70cf40816542c9d7d1caf13",
				r[0].Args[0],
			)

			file, err := os.ReadFile(
				"testdata/tx_receipt_1909952.json",
			)
			testSuite.NoError(err)

			receipt := new(types.Receipt)
			testSuite.NoError(receipt.UnmarshalJSON(file))
			*(r[0].Result.(**types.Receipt)) = receipt
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/block_response_1909952.json")
	testSuite.NoError(err)
	var correctResp *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correctResp))

	resp, err := c.Block(
		ctx,
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(1909952),
		},
	)
	testSuite.Equal(correctResp.Block, resp)
	testSuite.NoError(err)
}
