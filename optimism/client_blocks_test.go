package optimism

import (
	"math/big"
	"testing"

	OldEth "github.com/ethereum-optimism/optimism/l2geth"
	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"

	mock "github.com/stretchr/testify/mock"
	suite "github.com/stretchr/testify/suite"
	semaphore "golang.org/x/sync/semaphore"
)

// ClientBlocksTestSuite tests client blocks dispatching
type ClientBlocksTestSuite struct {
	suite.Suite

	mockJSONRPC         *mocks.JSONRPC
	mockGraphQL         *mocks.GraphQL
	mockCurrencyFetcher *mocks.CurrencyFetcher
	client              *Client
}

// SetupTest configures the test suite.
func (testSuite *ClientBlocksTestSuite) SetupTest() {
	testSuite.mockJSONRPC = &mocks.JSONRPC{}
	testSuite.mockGraphQL = &mocks.GraphQL{}
	testSuite.mockCurrencyFetcher = &mocks.CurrencyFetcher{}
	testSuite.client = &Client{
		c:               testSuite.mockJSONRPC,
		g:               testSuite.mockGraphQL,
		currencyFetcher: testSuite.mockCurrencyFetcher,
		traceSemaphore:  semaphore.NewWeighted(100),
	}
}

// TestBlocksSuite runs the ClientBlocksTestSuite.
func TestBlocksSuite(t *testing.T) {
	suite.Run(t, new(ClientBlocksTestSuite))
}

// TestToBlockNumArg tests [toBlockNumArg].
func (testSuite *ClientBlocksTestSuite) TestToBlockNumArg() {
	// A nil block number is the latest block.
	testSuite.Equal("latest", toBlockNumArg(nil))

	// A block number of -1 is pending.
	testSuite.Equal("pending", toBlockNumArg(big.NewInt(-1)))

	// All other block numbers are hex encoded.
	testSuite.Equal("0x0", toBlockNumArg(big.NewInt(0)))
	testSuite.Equal("0x1", toBlockNumArg(big.NewInt(1)))
	testSuite.Equal("0x4c5836", toBlockNumArg(big.NewInt(5003318)))

	// Let's throw a negative number at it to see what happens.
	testSuite.Equal("-0x4c5836", toBlockNumArg(big.NewInt(-5003318)))
}

// TestBlockByNumber tests [blockByNumber].
func (testSuite *ClientBlocksTestSuite) TestBlockByNumber() {
	index := int64(5003318)

	// An empty map should pass
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "0x4c5836", true).Return(nil).Once()
	fetchedBlock, err := testSuite.client.blockByNumber(nil, &index, true)
	testSuite.NoError(err)
	testSuite.Equal(map[string]interface{}{}, fetchedBlock)

	// Setting the r param to nil should error with ethereum.NotFound
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "0x4c5836", true).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*map[string]interface{})
			*r = nil
		},
	).Once()
	fetchedBlock, err = testSuite.client.blockByNumber(nil, &index, true)
	testSuite.Equal(OldEth.NotFound, err)
	testSuite.Nil(fetchedBlock)

	// Let's construct a correct block
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "0x4c5836", true).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*map[string]interface{})
			// Note: an actual block would be returned here, but we're just asserting the mapping is returned correctly
			*r = map[string]interface{}{
				"number": "0x4c5836",
			}
		},
	).Once()
	fetchedBlock, err = testSuite.client.blockByNumber(nil, &index, true)
	testSuite.NoError(err)
	testSuite.Equal(map[string]interface{}{
		"number": "0x4c5836",
	}, fetchedBlock)
}
