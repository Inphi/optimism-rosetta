package optimism

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"
	"github.com/inphi/optimism-rosetta/optimism/utilities/artifacts"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sync/semaphore"
)

// ClientBalanceSuite tests [Client.Balance].
type ClientBalanceSuite struct {
	suite.Suite

	mockJSONRPC *mocks.JSONRPC
	mockGraphQL *mocks.GraphQL
	client      *Client
}

// SetupTest sets up the test suite.
func (testSuite *ClientBalanceSuite) SetupTest() {
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

// TestBalanceSuite runs the ClientBalanceSuite.
func TestBalanceSuite(t *testing.T) {
	suite.Run(t, new(ClientBalanceSuite))
}

// TestBalance tests [Client.Balance].
func (testSuite *ClientBalanceSuite) TestBalance() {
	ctx := context.Background()

	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_10992.json")
			testSuite.NoError(err)

			*r = json.RawMessage(file)
		},
	).Once()

	blockNum := fmt.Sprintf("0x%s", strconv.FormatInt(10992, 16))
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 3 && rpcs[0].Method == "eth_getBalance" && rpcs[1].Method == "eth_getTransactionCount" && rpcs[2].Method == "eth_getCode"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 3)
			for i := range r {
				testSuite.Len(r[i].Args, 2)
				testSuite.Equal(r[i].Args[0], account)
				testSuite.Equal(r[i].Args[1], blockNum)
			}

			balance := hexutil.MustDecodeBig("0x2324c0d180077fe7000")
			*(r[0].Result.(*hexutil.Big)) = (hexutil.Big)(*balance)
			*(r[1].Result.(*hexutil.Uint64)) = hexutil.Uint64(0)
			*(r[2].Result.(*string)) = "0x"
		},
	).Once()

	callData, err := artifacts.ERC20ABI.Pack("balanceOf", common.HexToAddress(account))
	testSuite.NoError(err)
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_call",
		map[string]string{
			"data": fmt.Sprintf("0x%s", common.Bytes2Hex(callData)),
			"to":   opTokenContractAddress.String(),
		},
		blockNum,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*string)
			var expected map[string]interface{}
			file, err := os.ReadFile("testdata/call_balance_token_10992.json")
			testSuite.NoError(err)

			err = json.Unmarshal(file, &expected)
			testSuite.NoError(err)

			*r = expected["data"].(string)
		},
	).Once()

	resp, err := testSuite.client.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: account,
		},
		nil,
		nil,
	)
	testSuite.Equal(&RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  "0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
			Index: 10992,
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "10372550232136640000000",
				Currency: Currency,
			},
			{
				Value:    "1000000000000000000000",
				Currency: OPTokenCurrency,
			},
		},
		Metadata: map[string]interface{}{
			"code":  "0x",
			"nonce": int64(0),
		},
	}, resp)
	testSuite.NoError(err)
}

func (testSuite *ClientBalanceSuite) TestBalanceHistorical_Hash() {
	ctx := context.Background()
	blockNum := fmt.Sprintf("0x%s", strconv.FormatInt(10992, 16))

	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByHash",
		mock.Anything,
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			blockHash := *args.Get(3).(*string)
			testSuite.Equal("0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae", blockHash)

			r := args.Get(1).(*json.RawMessage)
			file, err := os.ReadFile("testdata/block_10992.json")
			testSuite.NoError(err)
			*r = json.RawMessage(file)
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 3 && rpcs[0].Method == "eth_getBalance" && rpcs[1].Method == "eth_getTransactionCount" && rpcs[2].Method == "eth_getCode"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 3)
			for i := range r {
				testSuite.Len(r[i].Args, 2)
				testSuite.Equal(r[i].Args[0], account)
				testSuite.Equal(r[i].Args[1], blockNum)
			}

			balance := hexutil.MustDecodeBig("0x2324c0d180077fe7000")
			*(r[0].Result.(*hexutil.Big)) = (hexutil.Big)(*balance)
			*(r[1].Result.(*hexutil.Uint64)) = hexutil.Uint64(0)
			*(r[2].Result.(*string)) = "0x"
		},
	).Once()

	callData, err := artifacts.ERC20ABI.Pack("balanceOf", common.HexToAddress(account))
	testSuite.NoError(err)
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_call",
		map[string]string{
			"data": fmt.Sprintf("0x%s", common.Bytes2Hex(callData)),
			"to":   opTokenContractAddress.String(),
		},
		blockNum,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*string)
			var expected map[string]interface{}
			file, err := os.ReadFile("testdata/call_balance_token_10992.json")
			testSuite.NoError(err)

			err = json.Unmarshal(file, &expected)
			testSuite.NoError(err)

			*r = expected["data"].(string)
		},
	).Once()

	resp, err := testSuite.client.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: account,
		},
		&RosettaTypes.PartialBlockIdentifier{
			Hash: RosettaTypes.String(
				"0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
			),
			Index: RosettaTypes.Int64(8165),
		},
		nil,
	)
	testSuite.Equal(&RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  "0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
			Index: 10992,
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "10372550232136640000000",
				Currency: Currency,
			},
			{
				Value:    "1000000000000000000000",
				Currency: OPTokenCurrency,
			},
		},
		Metadata: map[string]interface{}{
			"code":  "0x",
			"nonce": int64(0),
		},
	}, resp)
	testSuite.NoError(err)
}

func (testSuite *ClientBalanceSuite) TestBalanceHistorical_Index() {
	ctx := context.Background()
	blockNum := fmt.Sprintf("0x%s", strconv.FormatInt(10992, 16))

	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		blockNum,
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)
			file, err := os.ReadFile("testdata/block_10992.json")
			testSuite.NoError(err)
			*r = json.RawMessage(file)
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 3 && rpcs[0].Method == "eth_getBalance" && rpcs[1].Method == "eth_getTransactionCount" && rpcs[2].Method == "eth_getCode"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)

			testSuite.Len(r, 3)
			for i := range r {
				testSuite.Len(r[i].Args, 2)
				testSuite.Equal(r[i].Args[0], account)
				testSuite.Equal(r[i].Args[1], blockNum)
			}

			balance := hexutil.MustDecodeBig("0x2324c0d180077fe7000")
			*(r[0].Result.(*hexutil.Big)) = (hexutil.Big)(*balance)
			*(r[1].Result.(*hexutil.Uint64)) = hexutil.Uint64(0)
			*(r[2].Result.(*string)) = "0x"
		},
	).Once()

	callData, err := artifacts.ERC20ABI.Pack("balanceOf", common.HexToAddress(account))
	testSuite.NoError(err)
	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_call",
		map[string]string{
			"data": fmt.Sprintf("0x%s", common.Bytes2Hex(callData)),
			"to":   opTokenContractAddress.String(),
		},
		blockNum,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*string)
			var expected map[string]interface{}
			file, err := os.ReadFile("testdata/call_balance_token_10992.json")
			testSuite.NoError(err)

			err = json.Unmarshal(file, &expected)
			testSuite.NoError(err)

			*r = expected["data"].(string)
		},
	).Once()

	resp, err := testSuite.client.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: account,
		},
		&RosettaTypes.PartialBlockIdentifier{
			Index: RosettaTypes.Int64(10992),
		},
		nil,
	)
	testSuite.Equal(&RosettaTypes.AccountBalanceResponse{
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  "0xba9ded5ca1ec9adb9451bf062c9de309d9552fa0f0254a7b982d3daf7ae436ae",
			Index: 10992,
		},
		Balances: []*RosettaTypes.Amount{
			{
				Value:    "10372550232136640000000",
				Currency: Currency,
			},
			{
				Value:    "1000000000000000000000",
				Currency: OPTokenCurrency,
			},
		},
		Metadata: map[string]interface{}{
			"code":  "0x",
			"nonce": int64(0),
		},
	}, resp)
	testSuite.NoError(err)
}

func (testSuite *ClientBalanceSuite) TestBalanceInvalidAddress() {
	ctx := context.Background()

	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByNumber",
		"latest",
		false,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*json.RawMessage)

			file, err := os.ReadFile("testdata/block_10992.json")
			testSuite.NoError(err)

			*r = json.RawMessage(file)
		},
	).Once()
	testSuite.mockJSONRPC.On(
		"BatchCallContext",
		ctx,
		mock.MatchedBy(func(rpcs []rpc.BatchElem) bool {
			return len(rpcs) == 3 && rpcs[0].Method == "eth_getBalance" && rpcs[1].Method == "eth_getTransactionCount" && rpcs[2].Method == "eth_getCode"
		}),
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).([]rpc.BatchElem)
			testSuite.Len(r, 3)
			r[0].Error = fmt.Errorf("invalid argument 0")
		},
	).Once()

	resp, err := testSuite.client.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: "0x4cfc400fed52f9681b42454c2db4b18ab98f8de",
		},
		nil,
		nil,
	)
	testSuite.Nil(resp)
	testSuite.Error(err)
}

func (testSuite *ClientBalanceSuite) TestBalanceInvalidHash() {
	ctx := context.Background()
	invalidHash := "0x7d2a2713026a0e66f131878de2bb2df2fff6c24562c1df61ec0265e5fedf2626"

	testSuite.mockJSONRPC.On(
		"CallContext",
		ctx,
		mock.Anything,
		"eth_getBlockByHash",
		mock.Anything,
		false,
	).Return(
		fmt.Errorf("invalid argument"),
	).Run(
		func(args mock.Arguments) {
			blockHash := *args.Get(3).(*string)
			testSuite.Equal(invalidHash, blockHash)
		},
	).Once()

	resp, err := testSuite.client.Balance(
		ctx,
		&RosettaTypes.AccountIdentifier{
			Address: account,
		},
		&RosettaTypes.PartialBlockIdentifier{
			Hash: RosettaTypes.String(
				invalidHash,
			),
		},
		nil,
	)
	testSuite.Nil(resp)
	testSuite.Error(err)
}
