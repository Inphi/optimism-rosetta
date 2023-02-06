package optimism

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"testing"

	mocks "github.com/coinbase/rosetta-ethereum/mocks/optimism"
	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/eth"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sync/semaphore"
)

var (
	tracerTimeout          = "120s"
	loadedTracer           = "callTracer"
	testBedrockTraceConfig = &eth.TraceConfig{
		Timeout: &tracerTimeout,
		Tracer:  &loadedTracer,
	}
)

func TestBedrock_BlockCurrent(t *testing.T) {
	t.Skip()

	mockJSONRPC := &mocks.JSONRPC{}
	mockGraphQL := &mocks.GraphQL{}
	mockCurrencyFetcher := &mocks.CurrencyFetcher{}

	c := &Client{
		c:               mockJSONRPC,
		g:               mockGraphQL,
		currencyFetcher: mockCurrencyFetcher,
		tc:              testBedrockTraceConfig,
		p:               params.GoerliChainConfig,
		traceSemaphore:  semaphore.NewWeighted(100),
		filterTokens:    false,
	}

	ctx := context.Background()
	mockJSONRPC.On(
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

			file, err := ioutil.ReadFile("testdata/goerli_bedrock_block_5003318.json")
			assert.NoError(t, err)

			*r = json.RawMessage(file)
		},
	).Once()
	mockCurrencyFetcher.On(
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

	tx1 := common.HexToHash("0x035437471437d2e61be662be806ea7a3603e37230e13f1c04e36e8ca891e9611")
	tx2 := common.HexToHash("0x6103c9a945fabd69b2cfe25cd0f5c9ebe73b7f68f4fed2c68b2cfdd8429a6a88")

	mockDebugTraceTransaction(ctx, t, mockJSONRPC, tx1, "testdata/goerli_bedrock_tx_5003318_1.json")
	mockDebugTraceTransaction(ctx, t, mockJSONRPC, tx2, "testdata/goerli_bedrock_tx_5003318_2.json")
	mockGetTransactionReceipt(ctx, t, mockJSONRPC, []common.Hash{tx1, tx2}, []string{"testdata/goerli_bedrock_tx_receipt_5003318_1.json", "testdata/goerli_bedrock_tx_receipt_5003318_2.json"})

	correctRaw, err := ioutil.ReadFile("testdata/goerli_bedrock_block_response_5003318.json")
	assert.NoError(t, err)
	var correct *RosettaTypes.BlockResponse
	assert.NoError(t, json.Unmarshal(correctRaw, &correct))

	resp, err := c.Block(
		ctx,
		nil,
	)
	assert.Equal(t, correct.Block, resp)
	assert.NoError(t, err)

	mockJSONRPC.AssertExpectations(t)
	mockGraphQL.AssertExpectations(t)

}

func mockDebugTraceTransaction(ctx context.Context, t *testing.T, mockJSONRPC *mocks.JSONRPC, txhash common.Hash, txFileData string) {
	mockJSONRPC.On(
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

			assert.Len(t, r, 1)
			assert.Len(t, r[0].Args, 2)
			assert.Equal(
				t,
				txhash.Hex(),
				r[0].Args[0],
			)
			assert.Equal(t, testBedrockTraceConfig, r[0].Args[1])

			file, err := ioutil.ReadFile(txFileData)
			assert.NoError(t, err)

			call := new(Call)
			assert.NoError(t, call.UnmarshalJSON(file))
			*(r[0].Result.(**Call)) = call
		},
	).Once()
}

func mockGetTransactionReceipt(ctx context.Context, t *testing.T, mockJSONRPC *mocks.JSONRPC, txhashes []common.Hash, txFileData []string) {
	assert.Equal(t, len(txhashes), len(txFileData))
	numReceipts := len(txhashes)
	mockJSONRPC.On(
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

			assert.Len(t, r, numReceipts)
			for i := range txhashes {
				assert.Equal(
					t,
					txhashes[i].Hex(),
					r[i].Args[0],
				)

				file, err := ioutil.ReadFile(txFileData[i])
				assert.NoError(t, err)

				receipt := new(types.Receipt)
				assert.NoError(t, receipt.UnmarshalJSON(file))
				*(r[0].Result.(**types.Receipt)) = receipt
			}
		},
	).Once()
}
