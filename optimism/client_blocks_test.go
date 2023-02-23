package optimism

import (
	"errors"
	"math/big"
	"testing"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
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

// TestBlockWithFetchErrors tests the top-level client [Block] method.
func (testSuite *ClientBlocksTestSuite) TestBlockWithFetchErrors() {
	// Test Pre-bedrock block request
	testSuite.True(testSuite.client.IsPreBedrock(testSuite.client.bedrockBlock))

	// Test dispatching with a nil block identifier
	// This should result in the client calling for the latest block
	// Returning an error should then result in the dispatch function bubbling up the block fetch error
	expectedError := errors.New("test error")
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "latest", true).Return(
		expectedError,
	).Once()
	_, err := testSuite.client.Block(nil, nil)
	testSuite.Equal(expectedError, err)

	// Test dispatching with a block identifier containing a hash
	hash := "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774"
	identifier := RosettaTypes.PartialBlockIdentifier{
		Index: nil,
		Hash:  &hash,
	}
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByHash", "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774", true).Return(
		expectedError,
	).Once()
	_, err = testSuite.client.Block(nil, &identifier)
	testSuite.Equal(expectedError, err)

	// Test dispatching with a block identifier containing an index
	index := int64(5003318)
	identifier = RosettaTypes.PartialBlockIdentifier{
		Index: &index,
		Hash:  nil,
	}
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "0x4c5836", true).Return(
		expectedError,
	).Once()
	_, err = testSuite.client.Block(nil, &identifier)
	testSuite.Equal(expectedError, err)

	// Now switch to bedrock
	testSuite.client.bedrockBlock = big.NewInt(5003318)
	testSuite.False(testSuite.client.IsPreBedrock(testSuite.client.bedrockBlock))

	// Test dispatching with a nil block identifier
	// This should result in the client calling for the latest block
	// Returning an error should then result in the dispatch function bubbling up the block fetch error
	expectedError = errors.New("test error")
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "latest", true).Return(
		expectedError,
	).Once()
	_, err = testSuite.client.Block(nil, nil)
	testSuite.Equal(expectedError, err)

	// Test dispatching with a block identifier containing a hash
	hash = "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774"
	identifier = RosettaTypes.PartialBlockIdentifier{
		Index: nil,
		Hash:  &hash,
	}
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByHash", "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774", true).Return(
		expectedError,
	).Once()
	_, err = testSuite.client.Block(nil, &identifier)
	testSuite.Equal(expectedError, err)

	// Test dispatching with a block identifier containing an index
	index = int64(5003318)
	identifier = RosettaTypes.PartialBlockIdentifier{
		Index: &index,
		Hash:  nil,
	}
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "0x4c5836", true).Return(
		expectedError,
	).Once()
	_, err = testSuite.client.Block(nil, &identifier)
	testSuite.Equal(expectedError, err)
}

// TestBlockEmptyJsonRpcResponse tests the top-level client [Block] method.
func (testSuite *ClientBlocksTestSuite) TestBlockEmptyJsonRpcResponse() {
	// Test Pre-bedrock block request
	testSuite.True(testSuite.client.IsPreBedrock(testSuite.client.bedrockBlock))

	// Test dispatching with an empty json rpc block response
	expectedError := "unexpected end of JSON input"
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "latest", true).Return(
		nil,
	).Once()
	_, err := testSuite.client.Block(nil, nil)
	testSuite.Equal(expectedError, err.Error())

	// Test dispatching with a block identifier containing a hash
	hash := "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774"
	identifier := RosettaTypes.PartialBlockIdentifier{
		Index: nil,
		Hash:  &hash,
	}
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByHash", "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774", true).Return(
		nil,
	).Once()
	_, err = testSuite.client.Block(nil, &identifier)
	testSuite.Equal(expectedError, err.Error())

	// Test dispatching with a block identifier containing an index
	index := int64(5003318)
	identifier = RosettaTypes.PartialBlockIdentifier{
		Index: &index,
		Hash:  nil,
	}
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "0x4c5836", true).Return(
		nil,
	).Once()
	_, err = testSuite.client.Block(nil, &identifier)
	testSuite.Equal(expectedError, err.Error())

	// Now switch to bedrock
	testSuite.client.bedrockBlock = big.NewInt(5003318)
	testSuite.False(testSuite.client.IsPreBedrock(testSuite.client.bedrockBlock))

	// Post bedrock tests with empty json rpc response should also error
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "latest", true).Return(
		nil,
	).Once()
	_, err = testSuite.client.Block(nil, nil)
	testSuite.Equal(expectedError, err.Error())

	// Test dispatching with a block identifier containing a hash
	hash = "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774"
	identifier = RosettaTypes.PartialBlockIdentifier{
		Index: nil,
		Hash:  &hash,
	}
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByHash", "0x4503cbd671b3ca292e9f54998b2d566b705a32a178fc467f311c79b43e8e1774", true).Return(
		nil,
	).Once()
	_, err = testSuite.client.Block(nil, &identifier)
	testSuite.Equal(expectedError, err.Error())

	// Test dispatching with a block identifier containing an index
	index = int64(5003318)
	identifier = RosettaTypes.PartialBlockIdentifier{
		Index: &index,
		Hash:  nil,
	}
	testSuite.mockJSONRPC.On("CallContext", nil, mock.Anything, "eth_getBlockByNumber", "0x4c5836", true).Return(
		nil,
	).Once()
	_, err = testSuite.client.Block(nil, &identifier)
	testSuite.Equal(expectedError, err.Error())
}
