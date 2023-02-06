package optimism

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/core/types"
	"github.com/ethereum-optimism/optimism/l2geth/eth"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
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

	mockJSONRPC *mocks.JSONRPC
	mockGraphQL *mocks.GraphQL
}

func TestClientBedrock(t *testing.T) {
	suite.Run(t, new(ClientBedrockTestSuite))
}

func (testSuite *ClientBedrockTestSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
}

func (testSuite *ClientBedrockTestSuite) TestBedrock_BlockCurrent() {
	cf, err := newERC20CurrencyFetcher(testSuite.mockJSONRPC)
	testSuite.NoError(err)
	c := &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: cf,
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

	tx1 := common.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	tx2 := common.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88")

	mockDebugTraceTransaction(ctx, testSuite, tx1, "testdata/goerli_bedrock_tx_5003318_1.json")
	mockDebugTraceTransaction(ctx, testSuite, tx2, "testdata/goerli_bedrock_tx_5003318_2.json")
	mockGetTransactionReceipt(ctx, testSuite, []common.Hash{tx1, tx2}, []string{"testdata/goerli_bedrock_tx_receipt_5003318_1.json", "testdata/goerli_bedrock_tx_receipt_5003318_2.json"})

	correctRaw, err := os.ReadFile("testdata/goerli_bedrock_block_response_5003318.json")
	testSuite.NoError(err)
	var correct *RosettaTypes.BlockResponse
	testSuite.NoError(json.Unmarshal(correctRaw, &correct))

	// Fetch the latest block
	resp, err := c.Block(
		ctx,
		nil,
	)
	testSuite.Equal(correct.Block, resp)
	testSuite.NoError(err)
}

//nolint:unused
func mockDebugTraceTransaction(ctx context.Context, testSuite *ClientBedrockTestSuite, txhash common.Hash, txFileData string) {
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
func mockGetTransactionReceipt(ctx context.Context, testSuite *ClientBedrockTestSuite, txhashes []common.Hash, txFileData []string) {
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
