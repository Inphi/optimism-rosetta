package optimism

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sync/semaphore"
)

// ClientEstimateGasSuite tests [Client.EstimateGas].
type ClientEstimateGasSuite struct {
	suite.Suite

	mockJSONRPC *mocks.JSONRPC
	mockGraphQL *mocks.GraphQL
	client      *Client
}

// SetupTest sets up the test suite.
func (testSuite *ClientEstimateGasSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
	cf, err := newERC20CurrencyFetcher(testSuite.mockJSONRPC)
	testSuite.NoError(err)
	testSuite.client = &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: cf,
		traceSemaphore:  semaphore.NewWeighted(100),
	}
}

// TestSuite runs the ClientEstimateGasSuite.
func TestSuite(t *testing.T) {
	suite.Run(t, new(ClientEstimateGasSuite))
}

// TestClientEstimateGas tests [Client.EstimateGas].
func (testSuite *ClientEstimateGasSuite) TestClientEstimateGas() {
	ctx := context.Background()
	from := common.HexToAddress("0xE550f300E477C60CE7e7172d12e5a27e9379D2e3")
	to := common.HexToAddress("0xaD6D458402F60fD3Bd25163575031ACDce07538D")
	data := common.FromHex("0xa9059cbb000000000000000000000000ae7e48ee0f758cd706b76cf7e2175d982800879a" +
		"00000000000000000000000000000000000000000000000000521c5f98b8ea00")
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_estimateGas",
		mock.Anything,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*hexutil.Uint64)

			var expected map[string]interface{}
			file, err := os.ReadFile("testdata/estimate_gas_0xaD6D458402F60fD3Bd25163575031ACDce07538D.json")
			testSuite.NoError(err)

			err = json.Unmarshal(file, &expected)
			testSuite.NoError(err)

			*r = hexutil.Uint64(1)
		},
	).Once()

	correctRaw, err := os.ReadFile("testdata/estimate_gas_0xaD6D458402F60fD3Bd25163575031ACDce07538D.json")
	testSuite.NoError(err)
	var correct map[string]interface{}
	testSuite.NoError(json.Unmarshal(correctRaw, &correct))

	resp, err := testSuite.client.EstimateGas(ctx, ethereum.CallMsg{
		From: from,
		To:   &to,
		Data: data,
	})

	testSuite.Equal(uint64(1), resp)
	testSuite.NoError(err)
}
