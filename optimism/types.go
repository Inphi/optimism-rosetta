// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package optimism

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethTypes "github.com/ethereum/go-ethereum/core/types"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"

	EthCommon "github.com/ethereum/go-ethereum/common"
)

// Op Types
const (
	// MintOpType is a [RosettaTypes.Operation] type for an Optimism Deposit or "mint" transaction.
	MintOpType = "MINT"
	// An erroneous STOP Type not defined in rosetta-geth-sdk
	StopOpType = "STOP"
)

// ERC20 Log Consts
const (
	NumTopicsERC20Transfer = 3
	UnknownERC20Symbol     = "ERC20_UNKNOWN"
	UnknownERC20Decimals   = 0

	UnknownERC721Symbol   = "ERC721_UNKNOWN"
	UnknownERC721Decimals = 0
)

const (
	zeroAddress = "0x0000000000000000000000000000000000000000000000000000000000000000"
)

// Event Topics
const (
	// TransferEvent is emitted when an ERC20 token is transferred.
	//
	// TransferEvent is emitted in two bridging scenarios:
	// 1. When a native token is being sent to a non-native chain, from the sender to the bridge contract.
	//    Think: Transferring USDC on Ethereum Mainnet to the Optimism bridge contract,
	//    you will see a Transfer event from the sender (you) to the bridge contract.
	// 2. When a non-native token is being sent to a native chain, from the bridge to the sender contract.
	// 	  Think: "Withdrawing" USDC from Optimism to Ethereum Mainnet. You will see a Transfer event
	// 	  from the bridge contract to you (the sender) once the withdrawal is finalized on Mainnet.
	TransferEvent = "Transfer(address,address,uint256)"
)

// Optimism Predeploy Addresses (represented as 0x-prefixed hex string)
// See [PredeployedContracts] for more information.
//
// [PredeployedContracts]: https://github.com/ethereum-optimism/optimism/blob/d8e328ae936c6a5f3987c04cbde7bd94403a96a0/specs/predeploys.md
var (
	// The BaseFeeVault predeploy receives the basefees on L2.
	// The basefee is not burnt on L2 like it is on L1.
	// Once the contract has received a certain amount of fees,
	// the ETH can be permissionlessly withdrawn to an immutable address on L1.
	BaseFeeVault = EthCommon.HexToAddress("0x4200000000000000000000000000000000000019")

	// The L1FeeVault predeploy receives the L1 portion of the transaction fees.
	// Once the contract has received a certain amount of fees,
	// the ETH can be permissionlessly withdrawn to an immutable address on L1.
	L1FeeVault = EthCommon.HexToAddress("0x420000000000000000000000000000000000001a")
)

const (
	// NodeVersion is the version of geth we are using.
	NodeVersion = "1.9.24"

	// Blockchain is Optimism.
	Blockchain string = "Optimism"

	// MainnetNetwork is the value of the network
	// in MainnetNetworkIdentifier.
	MainnetNetwork string = "Mainnet"

	// TestnetNetwork is the value of the network
	// in TestnetNetworkIdentifier.
	TestnetNetwork string = "Testnet"

	// SepoliaNetwork is the value of the sepolia network.
	SepoliaNetwork string = "Sepolia"

	// GoerliNetwork is the value of the network
	// in GoerliNetworkNetworkIdentifier.
	GoerliNetwork string = "Goerli"

	// Symbol is the symbol value
	// used in Currency.
	Symbol = "ETH"

	TokenSymbol = "OP"

	// Decimals is the decimals value
	// used in Currency.
	Decimals = 18

	TokenDecimals = 18

	// FeeOpType is used to represent fee operations.
	FeeOpType = "FEE"

	// PaymentOpType is used to represent token transfer operations
	PaymentOpType = "PAYMENT"

	// ERC20MintOpType is used to represent token mint operations
	ERC20MintOpType = "ERC20_MINT"

	// ERC20BurnOpType is used to represent token burn operations
	ERC20BurnOpType = "ERC20_BURN"

	// ERC20TransferOpType is used to represent token transfer operations
	ERC20TransferOpType = "ERC20_TRANSFER"

	// CallOpType is used to represent CALL trace operations.
	CallOpType = "CALL"

	// CreateOpType is used to represent CREATE trace operations.
	CreateOpType = "CREATE"

	// Create2OpType is used to represent CREATE2 trace operations.
	Create2OpType = "CREATE2"

	// SelfDestructOpType is used to represent SELFDESTRUCT trace operations.
	SelfDestructOpType = "SELFDESTRUCT"

	// CallCodeOpType is used to represent CALLCODE trace operations.
	CallCodeOpType = "CALLCODE"

	// DelegateCallOpType is used to represent DELEGATECALL trace operations.
	DelegateCallOpType = "DELEGATECALL"

	// StaticCallOpType is used to represent STATICCALL trace operations.
	StaticCallOpType = "STATICCALL"

	// DestructOpType is a synthetic operation used to represent the
	// deletion of suicided accounts that still have funds at the end
	// of a transaction.
	DestructOpType = "DESTRUCT"

	// DelegateVotesOpType is used to represent OZ ERC20Votes votes delegation
	DelegateVotesOpType = "DELEGATE_VOTES"

	// SuccessStatus is the status of any
	// Ethereum operation considered successful.
	SuccessStatus = "SUCCESS"

	// FailureStatus is the status of any
	// Ethereum operation considered unsuccessful.
	FailureStatus = "FAILURE"

	// HistoricalBalanceSupported is whether
	// historical balance is supported.
	HistoricalBalanceSupported = true

	// GenesisBlockIndex is the index of the
	// genesis block.
	GenesisBlockIndex = int64(0)

	// TransferGasLimit is the gas limit
	// of a transfer.
	TransferGasLimit = uint64(21000) //nolint:gomnd

	// MainnetGethArguments are the arguments to start a mainnet geth instance.
	MainnetGethArguments = `--config=/app/optimism/geth.toml --gcmode=archive --graphql`

	// IncludeMempoolCoins does not apply to rosetta-ethereum as it is not UTXO-based.
	IncludeMempoolCoins = false

	// ContractAddressKey is the key used to denote the contract address
	// for a token, provided via Currency metadata.
	ContractAddressKey string = "token_address"
)

// RPC Methods
const (
	// EthGetTransactionReceipt is the RPC method used to fetch a transaction receipt.
	EthGetTransactionReceipt = "eth_getTransactionReceipt"

	// EthGetBlockByNumber is the RPC method used to fetch a block by number.
	EthGetBlockByNumber = "eth_getBlockByNumber"

	// EthCall is the RPC method used to call a contract.
	EthCall = "eth_call"

	// EthEstimateGas is the RPC method used to estimate gas.
	EthEstimateGas = "eth_estimateGas"
)

var (
	// TestnetGethArguments are the arguments to start a ropsten geth instance.
	TestnetGethArguments = fmt.Sprintf("%s --testnet", MainnetGethArguments)

	// RinkebyGethArguments are the arguments to start a rinkeby geth instance.
	RinkebyGethArguments = fmt.Sprintf("%s --rinkeby", MainnetGethArguments)

	// GoerliGethArguments are the arguments to start a ropsten geth instance.
	GoerliGethArguments = fmt.Sprintf("%s --goerli", MainnetGethArguments)

	// MainnetGenesisBlockIdentifier is the *types.BlockIdentifier
	// of the mainnet genesis block.
	MainnetGenesisBlockIdentifier = &types.BlockIdentifier{
		Hash:  "0x7ca38a1916c42007829c55e69d3e9a73265554b586a499015373241b8a3fa48b",
		Index: GenesisBlockIndex,
	}

	// TestnetGenesisBlockIdentifier is the *types.BlockIdentifier
	// of the testnet genesis block.
	TestnetGenesisBlockIdentifier = &types.BlockIdentifier{
		Hash:  "0x02adc9b449ff5f2467b8c674ece7ff9b21319d76c4ad62a67a70d552655927e5",
		Index: GenesisBlockIndex,
	}

	// GoerliGenesisBlockIdentifier is the *types.BlockIdentifier
	// of the Goerli genesis block.
	GoerliGenesisBlockIdentifier = &types.BlockIdentifier{
		Hash:  "0xb643d8aa991fb19f47b9178818886afb4eb54589eb500967beb444ea64f9761b",
		Index: GenesisBlockIndex,
	}

	SepoliaGenesisBlockIdentifier = &types.BlockIdentifier{
		Hash:  "0x102de6ffb001480cc9b8b548fd05c34cd4f46ae4aa91759393db90ea0409887d",
		Index: GenesisBlockIndex,
	}

	// Currency is the *types.Currency for all
	// Ethereum networks.
	Currency = &types.Currency{
		Symbol:   Symbol,
		Decimals: Decimals,
	}

	OPTokenCurrency = &types.Currency{
		Symbol:   TokenSymbol,
		Decimals: TokenDecimals,
	}

	// OperationTypes are all suppoorted operation types.
	OperationTypes = []string{
		FeeOpType,
		PaymentOpType,
		ERC20MintOpType,
		ERC20BurnOpType,
		CallOpType,
		CreateOpType,
		Create2OpType,
		SelfDestructOpType,
		CallCodeOpType,
		DelegateCallOpType,
		StaticCallOpType,
		DestructOpType,
		DelegateVotesOpType,
		ERC20TransferOpType,
	}

	// OperationStatuses are all supported operation statuses.
	OperationStatuses = []*types.OperationStatus{
		{
			Status:     SuccessStatus,
			Successful: true,
		},
		{
			Status:     FailureStatus,
			Successful: false,
		},
	}

	// CallMethods are all supported call methods.
	CallMethods = []string{
		EthGetBlockByNumber,
		EthGetTransactionReceipt,
		EthCall,
		EthEstimateGas,
	}
)

// JSONRPC is the interface for accessing go-ethereum's JSON RPC endpoint.
type JSONRPC interface {
	CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error
	BatchCallContext(ctx context.Context, b []rpc.BatchElem) error
	Close()
}

// GraphQL is the interface for accessing go-ethereum's GraphQL endpoint.
type GraphQL interface {
	Query(ctx context.Context, input string) (string, error)
}

// L2Receipt represents the results of a transaction.
type L2Receipt struct {
	// Consensus fields: These fields are defined by the Yellow Paper
	Type              *hexutil.Uint64 `json:"type,omitempty"`
	PostState         []byte          `json:"root"`
	Status            *hexutil.Uint64 `json:"status"`
	CumulativeGasUsed *hexutil.Uint64 `json:"cumulativeGasUsed"`
	Bloom             ethTypes.Bloom  `json:"logsBloom"`
	Logs              []*ethTypes.Log `json:"logs"`

	// Implementation fields: These fields are added by geth when processing a transaction or retrieving a receipt.
	// gencodec annotated fields: these are stored in the chain database.
	TxHash            common.Hash     `json:"transactionHash"`
	ContractAddress   *common.Address `json:"contractAddress"`
	GasUsed           *hexutil.Uint64 `json:"gasUsed"`
	EffectiveGasPrice *hexutil.Uint64 `json:"effectiveGasPrice,omitempty"` // required, but tag omitted for backwards compatibility
	BlobGasUsed       *hexutil.Uint64 `json:"blobGasUsed,omitempty"`
	BlobGasPrice      *hexutil.Uint64 `json:"blobGasPrice,omitempty"`

	// DepositNonce was introduced in Regolith to store the actual nonce used by deposit transactions
	// The state transition process ensures this is only set for Regolith deposit transactions.
	DepositNonce *hexutil.Uint64 `json:"depositNonce,omitempty"`
	// DepositReceiptVersion was introduced in Canyon to indicate an update to how receipt hashes
	// should be computed when set. The state transition process ensures this is only set for
	// post-Canyon deposit transactions.
	DepositReceiptVersion *hexutil.Uint64 `json:"depositReceiptVersion,omitempty"`

	// Inclusion information: These fields provide information about the inclusion of the
	// transaction corresponding to this receipt.
	BlockHash        common.Hash     `json:"blockHash,omitempty"`
	BlockNumber      *hexutil.Uint64 `json:"blockNumber,omitempty"`
	TransactionIndex *hexutil.Uint64 `json:"transactionIndex"`

	// OVM legacy: extend receipts with their L1 price (if a rollup tx)
	L1GasPrice *hexutil.Uint64 `json:"l1GasPrice,omitempty"`
	L1GasUsed  *hexutil.Uint64 `json:"l1GasUsed,omitempty"`
	L1Fee      *hexutil.Uint64 `json:"l1Fee,omitempty"`
	FeeScalar  *big.Float      `json:"l1FeeScalar,omitempty"` // always nil after Ecotone hardfork
}

// CallType returns a boolean indicating
// if the provided trace type is a call type.
func CallType(t string) bool {
	callTypes := []string{
		CallOpType,
		CallCodeOpType,
		DelegateCallOpType,
		StaticCallOpType,
	}

	for _, callType := range callTypes {
		if callType == t {
			return true
		}
	}

	return false
}

// CreateType returns a boolean indicating
// if the provided trace type is a create type.
func CreateType(t string) bool {
	createTypes := []string{
		CreateOpType,
		Create2OpType,
	}

	for _, createType := range createTypes {
		if createType == t {
			return true
		}
	}

	return false
}
