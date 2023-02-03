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
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"time"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	ethereum "github.com/ethereum-optimism/optimism/l2geth"
	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/common/hexutil"
	"github.com/ethereum-optimism/optimism/l2geth/core/types"
	"github.com/ethereum-optimism/optimism/l2geth/eth"
	"github.com/ethereum-optimism/optimism/l2geth/params"
	"github.com/ethereum-optimism/optimism/l2geth/rlp"
	"github.com/ethereum-optimism/optimism/l2geth/rpc"
	"github.com/inphi/optimism-rosetta/optimism/utilities/artifacts"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/sync/semaphore"
)

const (
	defaultHTTPTimeout    = 240 * time.Second
	defaultTraceCacheSize = 20

	defaultMaxTraceConcurrency = int64(1) // nolint:gomnd
	semaphoreTraceWeight       = int64(1) // nolint:gomnd

	burnSelector          = "0x9dc29fac" // keccak(burn(address,uint256))
	mintSelector          = "0x40c10f19" // keccak(mint(address,uint256))
	erc20TransferSelector = "0xa9059cbb" // keccak(transfer(address,uint256))
	fnSelectorLen         = 10
	j
	sequencerFeeVaultAddr = "0x4200000000000000000000000000000000000011"
	zeroAddr              = "0x0000000000000000000000000000000000000000"

	erc20TransferEventLogTopics = "Transfer(address,address,uint256)"

	// While parsing ERC20 ops, we will ignore any event logs that we think are an ERC20 tansfer
	// that do not contain 3 topics and who's 'data' field is not a single 32 byte hex string representing the amount of the transfer
	numTopicsERC20Transfer = 3

	// Fees on L2 weren't enforced on Goerli prior to this block height. This meant that transactions with a zero gas price were accepted without paying any fees
	goerliRollupFeeEnforcementBlockHeight = 962297
)

var (
	ovmEthAddr         = common.HexToAddress("0xdeaddeaddeaddeaddeaddeaddeaddeaddead0000")
	gasPriceOracleAddr = common.HexToAddress("0x420000000000000000000000000000000000000f")
	// TODO: load the gpo owner from a config
	gasPriceOracleOwnerMainnet = common.HexToAddress("0x7107142636C85c549690b1Aca12Bdb8052d26Ae6")
	gasPriceOracleOwnerKovan   = common.HexToAddress("0x84f70449f90300997840eCb0918873745Ede7aE6")
	gasPriceOracleOwnerGoerli  = common.HexToAddress("0xa693B8f8207FF043F6bbC2E2120bbE4C2251Efe9")

	// The following mainnet block hashes have transaction (hashes) that are also present in succeeding blocks.
	// This occured due to a bug in contract whitelisting. Unfortunately eth_getTransactionByX now returns the succeeding block rather than the original.
	// This is only an issue when reconciling account balances of the affected contracts.
	// We fix this by hardcoding the original tx fees rather using the computed fees in the succeeding block (which had different block fee parameters at the time).
	originalFeeAmountInDupTx = map[string]string{
		"0x09b353fbfa414ff7765e9af807f488110775d55cfeee7df9ef3ee47e2aa0e9b9": "0x1c749d072a0258", // block height 985
		"0x5471d82d53ccbddaf43c0fe223d97b125a80fc10ef006eb0fdf6ba3ec326ff39": "0x208e99382fa09c", // 19022
		"0x5572ca94f6ef220f754ee486190a15c43aadcdfb2371ed3be1cd2d20f6edd96f": "0x19d4bf57ba1d5c", // 45036
		"0x14a46bae4ae839106d7b45c6110dcf3935b38ed9b5701eb51c0450317b4abd2e": "0xab05782f225c1",  // 123322
		"0x5a24e459391c24d364497d914024edb75823547dc44573ee3ae965cb613fca16": "0xae5ab279b6d9f",  // 123542
		"0x336c8e5427d7049b0469aa23a61f52cecedcb5f41bde3a1684ba84136c6068e3": "0x1faece70f1455b", // 1133328
		"0x1b3207bf43acb6a72e188edd91bced8abea2dd0edc47587db3e142ba10b7e001": "0x1f25f9be77ec1a", // 1135391
		"0x638a3a797476c8a9b9ed5d6aa88e2e59e1b562fb4853f253c7c08753a7a285fb": "0x14c4434ea24463", // 1144468
		"0x8fb9a287ccbe52b9ad39b47c95837ef257c3b684028e3ce2185bdf41d18646fa": "0x2f0664e5df8938", // 1244152
		"0x2c987042c2af3e009ef8d2cebcdf659faaa694089e0f9231202f3efdcb6562b8": "0x3f69ca816a72d6", // 1272994
	}

	opTokenContractAddress = common.HexToAddress("0x4200000000000000000000000000000000000042")

	// This contract accidentally triggered an Optimism bug on mainnet whereby its self destruction failed to relinquish its ETH
	// See https://www.saurik.com/optimism.html for the details
	opBugAccidentalTriggerContract = common.HexToAddress("0x40C539BBe076b91FdF681E6B4B84bd1Fe1F148d9")
	opBugAccidentalTriggerTx       = "0x3ff079ba4ea0745401e9661d623550d24c9412ea9ad578bfbb0d441dadcce9bc"

	goerliChainID = big.NewInt(420)
)

// Client allows for querying a set of specific Ethereum endpoints in an
// idempotent manner. Client relies on the eth_*, debug_*, and admin_*
// methods and on the graphql endpoint.
//
// Client borrows HEAVILY from https://github.com/ethereum/go-ethereum/tree/master/ethclient.
type Client struct {
	p          *params.ChainConfig
	tc         *eth.TraceConfig
	traceCache TraceCache

	c JSONRPC
	g GraphQL

	currencyFetcher CurrencyFetcher
	traceSemaphore  *semaphore.Weighted
	filterTokens    bool
	supportedTokens map[string]bool
	supportsSyncing bool
	skipAdminCalls  bool
	supportsPeering bool
	bedrockBlock    *big.Int
}

type ClientOptions struct {
	HTTPTimeout         time.Duration
	MaxTraceConcurrency int64
	EnableTraceCache    bool
	EnableGethTracer    bool
	FilterTokens        bool
	SupportedTokens     map[string]bool
	BedrockBlock        *big.Int
	SuportsSyncing      bool
	SkipAdminCalls      bool
	SupportsPeering     bool
}

// NewClient creates a Client that from the provided url and params.
func NewClient(url string, params *params.ChainConfig, opts ClientOptions) (*Client, error) {
	if opts.HTTPTimeout == 0 {
		opts.HTTPTimeout = defaultHTTPTimeout
	}
	c, err := rpc.DialHTTPWithClient(url, &http.Client{
		Timeout: opts.HTTPTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: unable to dial node", err)
	}

	tspec := tracerSpec{
		TracerPath:    defaultTracerPath,
		UseGethTracer: opts.EnableGethTracer,
	}
	log.Printf("tracer spec: %#v", tspec)
	tc, err := loadTraceConfig(tspec, opts.HTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to load trace config", err)
	}

	g, err := newGraphQLClient(url, opts.HTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to create GraphQL client", err)
	}

	currencyFetcher, err := newERC20CurrencyFetcher(c)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to create CurrencyFetcher", err)
	}

	if opts.MaxTraceConcurrency == 0 {
		opts.MaxTraceConcurrency = defaultMaxTraceConcurrency
	}
	log.Printf("max trace concurrency is %d", opts.MaxTraceConcurrency)

	var traceCache TraceCache
	if opts.EnableTraceCache {
		log.Println("using trace cache")
		if traceCache, err = NewTraceCache(c, tspec, opts.HTTPTimeout, defaultTraceCacheSize); err != nil {
			return nil, fmt.Errorf("%w: unable to create trace cache", err)
		}
	}

	return &Client{
		p:               params,
		tc:              tc,
		c:               c,
		g:               g,
		currencyFetcher: currencyFetcher,
		traceSemaphore:  semaphore.NewWeighted(opts.MaxTraceConcurrency),
		traceCache:      traceCache,
		filterTokens:    opts.FilterTokens,
		supportedTokens: opts.SupportedTokens,
		supportsSyncing: opts.SuportsSyncing,
		skipAdminCalls:  opts.SkipAdminCalls,
		supportsPeering: opts.SupportsPeering,
		bedrockBlock:    opts.BedrockBlock,
	}, nil
}

// Close shuts down the RPC client connection.
func (ec *Client) Close() {
	ec.c.Close()
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
func (ec *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "eth_getTransactionCount", account, "pending")
	return uint64(result), err
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (ec *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, "eth_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (ec *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}
	return ec.c.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Encode(data))
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	pending := big.NewInt(-1)
	if number.Cmp(pending) == 0 {
		return "pending"
	}
	return hexutil.EncodeBig(number)
}

func (ec *Client) getTransactionTraces(
	ctx context.Context,
	txs []rpcTransaction,
) ([]*Call, error) {
	if err := ec.traceSemaphore.Acquire(ctx, semaphoreTraceWeight); err != nil {
		return nil, err
	}
	defer ec.traceSemaphore.Release(semaphoreTraceWeight)

	traces := make([]*Call, len(txs))
	if len(txs) == 0 {
		return traces, nil
	}

	if ec.traceCache != nil {
		for i := range txs {
			result, err := ec.traceCache.FetchTransaction(ctx, txs[i].tx.Hash())
			if err != nil {
				return nil, err
			}
			traces[i] = result
		}
		return traces, nil
	}

	// Fetch traces sequentially to avoid DoS'ing the backend
	for i := range txs {
		req := rpc.BatchElem{
			Method: "debug_traceTransaction",
			Args:   []interface{}{txs[i].tx.Hash().Hex(), ec.tc},
			Result: &traces[i],
		}
		// TODO: Don't batch 1-sized requests
		if err := ec.c.BatchCallContext(ctx, []rpc.BatchElem{req}); err != nil {
			return nil, err
		}
		if req.Error != nil {
			return nil, req.Error
		}
		if traces[i] == nil {
			return nil, fmt.Errorf("got empty trace for %x", txs[i].tx.Hash().Hex())
		}
	}

	return traces, nil
}

func (ec *Client) getBlockReceipts(
	ctx context.Context,
	blockHash common.Hash,
	txs []rpcTransaction,
) ([]*types.Receipt, error) {
	receipts := make([]*types.Receipt, len(txs))
	if len(txs) == 0 {
		return receipts, nil
	}

	reqs := make([]rpc.BatchElem, len(txs))
	for i := range reqs {
		reqs[i] = rpc.BatchElem{
			Method: EthGetTransactionReceipt,
			Args:   []interface{}{txs[i].tx.Hash().Hex()},
			Result: &receipts[i],
		}
	}
	if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
		return nil, err
	}
	for i := range reqs {
		if reqs[i].Error != nil {
			return nil, reqs[i].Error
		}
		if receipts[i] == nil {
			return nil, fmt.Errorf("got empty receipt for %x", txs[i].tx.Hash().Hex())
		}
		if receipts[i].BlockHash.Hex() != blockHash.Hex() && !blockContainsDuplicateTransaction(blockHash) {
			return nil, fmt.Errorf(
				"%w: expected block hash %s for transaction but got %s",
				ErrBlockOrphaned,
				blockHash.Hex(),
				receipts[i].BlockHash.Hex(),
			)
		}
	}

	return receipts, nil
}

//nolint:gocognit
func (ec *Client) erc20TokenOps(
	ctx context.Context,
	block *types.Block,
	tx *legacyTransaction,
	startIndex int,
) ([]*RosettaTypes.Operation, error) {
	receipt := tx.Receipt

	ops := []*RosettaTypes.Operation{}
	var status string
	if receipt.Status == 1 {
		status = SuccessStatus
	} else {
		status = FailureStatus
	}

	keccak := crypto.Keccak256([]byte(erc20TransferEventLogTopics))
	encodedTransferMethod := hexutil.Encode(keccak)

	// To handle cases such as out-of-gas errors, where no logs are emitted
	if status == FailureStatus && len(receipt.Logs) == 0 {
		input := strings.ToLower(tx.Trace.Input)

		// special case for failed ERC20 token transfers
		if strings.HasPrefix(input, erc20TransferSelector) {
			if toAddress, amount, err := decodeAddressUint256(input[fnSelectorLen:]); err == nil {
				contractAddress := tx.Trace.To.String()
				fromAddress := tx.Trace.From.String()
				currency, err := ec.currencyFetcher.FetchCurrency(ctx, block.NumberU64(), contractAddress)
				// If an error is encountered while fetching currency details, return a default value and let the client handle it.
				if err != nil {
					log.Printf("error while fetching currency details for currency: %s: %v", contractAddress, err)
					currency = &RosettaTypes.Currency{
						Symbol:   defaultERC20Symbol,
						Decimals: defaultERC20Decimals,
						Metadata: map[string]interface{}{
							ContractAddressKey: contractAddress,
						},
					}
				}
				ops = appendERC20Operations(ops, fromAddress, toAddress.String(), amount, currency, startIndex, status)
			}
		}
	}

	for _, receiptLog := range receipt.Logs {
		// If this isn't an ERC20 transfer, skip
		if !containsTopic(receiptLog, encodedTransferMethod) {
			continue
		}
		if len(receiptLog.Topics) != numTopicsERC20Transfer {
			continue
		}

		value := new(big.Int).SetBytes(receiptLog.Data)
		// If value <= 0, skip to the next receiptLog. Otherwise, proceed to generate the debit + credit operations.
		if value.Cmp(big.NewInt(0)) < 1 {
			continue
		}

		contractAddress := receiptLog.Address.String()
		_, ok := ChecksumAddress(contractAddress)
		if !ok {
			return nil, fmt.Errorf("%s is not a valid address", contractAddress)
		}
		// If it's a deposit tx, skip
		if contractAddress == ovmEthAddr.String() {
			continue
		}

		_, ok = ec.supportedTokens[strings.ToLower(contractAddress)]
		if ec.filterTokens && !ok {
			continue
		}

		fromAddress := common.HexToAddress(receiptLog.Topics[1].Hex()).String()
		_, ok = ChecksumAddress(fromAddress)
		if !ok {
			return nil, fmt.Errorf("%s is not a valid address", fromAddress)
		}

		toAddress := common.HexToAddress(receiptLog.Topics[2].Hex()).String()
		_, ok = ChecksumAddress(toAddress)
		if !ok {
			return nil, fmt.Errorf("%s is not a valid address", toAddress)
		}

		currency, err := ec.currencyFetcher.FetchCurrency(ctx, block.NumberU64(), contractAddress)
		// If an error is encountered while fetching currency details, return a default value and let the client handle it.
		if err != nil {
			log.Printf("error while fetching currency details for currency: %s: %v", contractAddress, err)
			currency = &RosettaTypes.Currency{
				Symbol:   defaultERC20Symbol,
				Decimals: defaultERC20Decimals,
				Metadata: map[string]interface{}{
					ContractAddressKey: contractAddress,
				},
			}
		}

		ops = appendERC20Operations(ops, fromAddress, toAddress, value, currency, startIndex, status)
	}

	return ops, nil
}

func appendERC20Operations(ops []*RosettaTypes.Operation,
	fromAddress string,
	toAddress string,
	value *big.Int,
	currency *RosettaTypes.Currency,
	startIndex int,
	status string) []*RosettaTypes.Operation {
	if fromAddress == zeroAddr {
		mintOp := &RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: int64(len(ops) + startIndex),
			},
			Type:   ERC20MintOpType,
			Status: RosettaTypes.String(status),
			Account: &RosettaTypes.AccountIdentifier{
				Address: toAddress,
			},
			Amount: &RosettaTypes.Amount{
				Value:    value.String(),
				Currency: currency,
			},
		}
		ops = append(ops, mintOp)
		return ops
	}

	if toAddress == zeroAddr {
		burnOp := &RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: int64(len(ops) + startIndex),
			},
			Type:   ERC20BurnOpType,
			Status: RosettaTypes.String(status),
			Account: &RosettaTypes.AccountIdentifier{
				Address: fromAddress,
			},
			Amount: &RosettaTypes.Amount{
				Value:    new(big.Int).Neg(value).String(),
				Currency: currency,
			},
		}
		ops = append(ops, burnOp)
		return ops
	}

	fromOp := &RosettaTypes.Operation{
		OperationIdentifier: &RosettaTypes.OperationIdentifier{
			Index: int64(len(ops) + startIndex),
		},
		Type:   PaymentOpType,
		Status: RosettaTypes.String(status),
		Account: &RosettaTypes.AccountIdentifier{
			Address: fromAddress,
		},
		Amount: &RosettaTypes.Amount{
			Value:    new(big.Int).Neg(value).String(),
			Currency: currency,
		},
	}

	ops = append(ops, fromOp)

	lastOpIndex := ops[len(ops)-1].OperationIdentifier.Index
	toOp := &RosettaTypes.Operation{
		OperationIdentifier: &RosettaTypes.OperationIdentifier{
			Index: lastOpIndex + 1,
		},
		RelatedOperations: []*RosettaTypes.OperationIdentifier{
			{
				Index: lastOpIndex,
			},
		},
		Type:   PaymentOpType,
		Status: RosettaTypes.String(status),
		Account: &RosettaTypes.AccountIdentifier{
			Address: toAddress,
		},
		Amount: &RosettaTypes.Amount{
			Value:    value.String(),
			Currency: currency,
		},
	}

	ops = append(ops, toOp)
	return ops
}

func blockContainsDuplicateTransaction(blockHash common.Hash) bool {
	return originalFeeAmountInDupTx[blockHash.Hex()] != ""
}

func containsTopic(log *types.Log, topic string) bool {
	for _, t := range log.Topics {
		hex := t.Hex()
		if hex == topic {
			return true
		}
	}
	return false
}

// traceOps returns all *RosettaTypes.Operation for a given
// array of flattened traces.
func traceOps(block *types.Block, calls []*FlatCall, startIndex int) []*RosettaTypes.Operation { // nolint: gocognit
	var ops []*RosettaTypes.Operation
	if len(calls) == 0 {
		return ops
	}

	destroyedAccounts := map[string]*big.Int{}
	for _, trace := range calls {
		// Rejected transactions do not produce traces (ex: attempts to deploy contracts that aren't in the Optimism whitelist)
		if trace.Type == "" {
			continue
		}

		// Handle partial transaction success
		metadata := map[string]interface{}{}
		opStatus := SuccessStatus
		if trace.Revert {
			opStatus = FailureStatus
			metadata["error"] = trace.ErrorMessage
		}

		var zeroValue bool
		if trace.Value.Sign() == 0 {
			zeroValue = true
		}

		// Skip all 0 value CallType operations (TODO: make optional to include)
		//
		// We can't continue here because we may need to adjust our destroyed
		// accounts map if a CallTYpe operation resurrects an account.
		shouldAdd := true
		if zeroValue && CallType(trace.Type) {
			shouldAdd = false
		}

		var (
			burnCall     bool
			mintCall     bool
			burnMintAddr common.Address
			burnMintAmt  *big.Int
		)

		// either we're burning or minting OVM_ETH
		if trace.Type == CallOpType && trace.To.Hex() == ovmEthAddr.Hex() {
			burnCall = strings.HasPrefix(trace.Input, burnSelector)
			mintCall = strings.HasPrefix(trace.Input, mintSelector)
			if burnCall || mintCall {
				var err error
				burnMintAddr, burnMintAmt, err = decodeAddressUint256(trace.Input[fnSelectorLen:])
				if err != nil {
					burnMintAddr, burnMintAmt = common.Address{}, nil
				}
			}
		}

		// Checksum addresses
		from := MustChecksum(trace.From.String())
		to := MustChecksum(trace.To.String())

		if shouldAdd {
			value := new(big.Int).Neg(trace.Value).String()
			// The OP bug here means that the ETH balance of the self-destructed contract remains unchanged
			// TODO(inphi): Bedrock fixes this
			if block.Transactions()[0].Hash().String() == opBugAccidentalTriggerTx &&
				opStatus == SuccessStatus &&
				trace.Type == SelfDestructOpType &&
				from == opBugAccidentalTriggerContract.String() {
				value = new(big.Int).String()
			}

			fromOp := &RosettaTypes.Operation{
				OperationIdentifier: &RosettaTypes.OperationIdentifier{
					Index: int64(len(ops) + startIndex),
				},
				Type:   trace.Type,
				Status: RosettaTypes.String(opStatus),
				Account: &RosettaTypes.AccountIdentifier{
					Address: from,
				},
				Amount: &RosettaTypes.Amount{
					Value:    value,
					Currency: Currency,
				},
				Metadata: metadata,
			}
			if zeroValue {
				fromOp.Amount = nil
			} else {
				_, destroyed := destroyedAccounts[from]
				if destroyed && opStatus == SuccessStatus {
					destroyedAccounts[from] = new(big.Int).Sub(destroyedAccounts[from], trace.Value)
				}
			}

			ops = append(ops, fromOp)
		}
		if burnCall {
			// if we are handling a burn of ovmEth, `shouldAdd` is disabled for the entirety of the iteration for this trace call
			burnDebitOp := &RosettaTypes.Operation{
				OperationIdentifier: &RosettaTypes.OperationIdentifier{
					Index: int64(len(ops) + startIndex),
				},
				Type:   trace.Type,
				Status: RosettaTypes.String(opStatus),
				Account: &RosettaTypes.AccountIdentifier{
					Address: burnMintAddr.String(),
				},
				Amount: &RosettaTypes.Amount{
					Value:    new(big.Int).Neg(burnMintAmt).String(),
					Currency: Currency,
				},
				Metadata: metadata,
			}
			ops = append(ops, burnDebitOp)

			lastOpIndex := ops[len(ops)-1].OperationIdentifier.Index
			burnCreditOp := &RosettaTypes.Operation{
				OperationIdentifier: &RosettaTypes.OperationIdentifier{
					Index: int64(len(ops) + startIndex),
				},
				RelatedOperations: []*RosettaTypes.OperationIdentifier{
					{
						Index: lastOpIndex,
					},
				},
				Type:   trace.Type,
				Status: RosettaTypes.String(opStatus),
				Account: &RosettaTypes.AccountIdentifier{
					Address: zeroAddr,
				},
				Amount: &RosettaTypes.Amount{
					Value:    burnMintAmt.String(),
					Currency: Currency,
				},
				Metadata: metadata,
			}
			ops = append(ops, burnCreditOp)
		}
		if mintCall {
			mintOp := &RosettaTypes.Operation{
				OperationIdentifier: &RosettaTypes.OperationIdentifier{
					Index: int64(len(ops) + startIndex),
				},
				Type:   trace.Type,
				Status: RosettaTypes.String(opStatus),
				Account: &RosettaTypes.AccountIdentifier{
					Address: burnMintAddr.String(),
				},
				Amount: &RosettaTypes.Amount{
					Value:    burnMintAmt.String(),
					Currency: Currency,
				},
				Metadata: metadata,
			}
			ops = append(ops, mintOp)
		}

		// Add to destroyed accounts if SELFDESTRUCT
		// and overwrite existing balance.

		// OVM hack: The OVM models SELFDESTRUCT as a couple of Add and Sub balance operations. See https://github.com/ethereum-optimism/optimism/issues/2604
		// for context.
		// We do the same here by permitting the shouldAdd check work on both sides of the Value transfer. Otherwise, the destroyed account will seem to
		// have a negative balance.
		// TODO(inphi): Bedrock fixes this. Uncomment this once Bedrock is up
		/*
			if trace.Type == SelfDestructOpType {
				destroyedAccounts[from] = new(big.Int)

				// If destination of of SELFDESTRUCT is self,
				// we should skip. In the EVM, the balance is reset
				// after the balance is increased on the destination
				// so this is a no-op.
				if from == to {
					continue
				}
			}
		*/

		// Skip empty to addresses (this may not
		// actually occur but leaving it as a
		// sanity check)
		if len(trace.To.String()) == 0 {
			continue
		}

		// If the account is resurrected, we remove it from
		// the destroyed accounts map.
		if CreateType(trace.Type) {
			delete(destroyedAccounts, to)
		}

		if shouldAdd {
			lastOpIndex := ops[len(ops)-1].OperationIdentifier.Index
			toOp := &RosettaTypes.Operation{
				OperationIdentifier: &RosettaTypes.OperationIdentifier{
					Index: lastOpIndex + 1,
				},
				RelatedOperations: []*RosettaTypes.OperationIdentifier{
					{
						Index: lastOpIndex,
					},
				},
				Type:   trace.Type,
				Status: RosettaTypes.String(opStatus),
				Account: &RosettaTypes.AccountIdentifier{
					Address: to,
				},
				Amount: &RosettaTypes.Amount{
					Value:    trace.Value.String(),
					Currency: Currency,
				},
				Metadata: metadata,
			}
			if zeroValue {
				toOp.Amount = nil
			} else {
				_, destroyed := destroyedAccounts[to]
				if destroyed && opStatus == SuccessStatus {
					destroyedAccounts[to] = new(big.Int).Add(destroyedAccounts[to], trace.Value)
				}
			}

			ops = append(ops, toOp)
		}
	}

	// Zero-out all destroyed accounts that are removed
	// during transaction finalization.
	for acct, val := range destroyedAccounts {
		if val.Sign() == 0 {
			continue
		}

		if val.Sign() < 0 {
			log.Fatalf("negative balance for suicided account %s: %s\n", acct, val.String())
		}

		ops = append(ops, &RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: ops[len(ops)-1].OperationIdentifier.Index + 1,
			},
			Type:   DestructOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: acct,
			},
			Amount: &RosettaTypes.Amount{
				Value:    new(big.Int).Neg(val).String(),
				Currency: Currency,
			},
		})
	}

	return ops
}

func decodeAddressUint256(hex string) (common.Address, *big.Int, error) {
	if len(hex) != 128 {
		return common.Address{}, nil, fmt.Errorf("invalid hex string length")
	}

	addrB := hex[:64]
	addr := common.HexToAddress(addrB)

	uint256Str := strings.TrimLeft(hex[64:], "0")
	if uint256Str == "" {
		uint256Str = "0"
	}
	bigHex := fmt.Sprintf("0x%s", uint256Str)
	uint256, err := hexutil.DecodeBig(bigHex)
	if err != nil {
		return common.Address{}, nil, err
	}
	return addr, uint256, nil
}

// transactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (ec *Client) transactionReceipt(
	ctx context.Context,
	txHash common.Hash,
) (*types.Receipt, error) {
	var r *types.Receipt
	err := ec.c.CallContext(ctx, &r, EthGetTransactionReceipt, txHash)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}

	return r, err
}

func (ec *Client) blockByNumber(
	ctx context.Context,
	index *int64,
	showTxDetails bool,
) (map[string]interface{}, error) {
	var blockIndex string
	if index == nil {
		blockIndex = toBlockNumArg(nil)
	} else {
		blockIndex = toBlockNumArg(big.NewInt(*index))
	}

	r := make(map[string]interface{})
	err := ec.c.CallContext(ctx, &r, "eth_getBlockByNumber", blockIndex, showTxDetails)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}

	return r, err
}

// contractCall returns the data specified by the given contract method
func (ec *Client) contractCall(
	ctx context.Context,
	params map[string]interface{},
) (map[string]interface{}, error) {
	// validate call input
	input, err := validateCallInput(params)
	if err != nil {
		return nil, err
	}

	// default query
	blockQuery := "latest"

	// if block number or hash, override blockQuery
	if input.BlockIndex > int64(0) {
		blockQuery = toBlockNumArg(big.NewInt(input.BlockIndex))
	} else if len(input.BlockHash) > 0 {
		blockQuery = input.BlockHash
	}

	// ensure valid contract address
	_, ok := ChecksumAddress(input.To)
	if !ok {
		return nil, ErrCallParametersInvalid
	}

	// parameters for eth_call
	callParams := map[string]string{
		"to":   input.To,
		"data": input.Data,
	}

	var resp string
	if err := ec.c.CallContext(ctx, &resp, "eth_call", callParams, blockQuery); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data": resp,
	}, nil
}

// estimateGas returns the data specified by the given contract method
func (ec *Client) estimateGas(
	ctx context.Context,
	params map[string]interface{},
) (map[string]interface{}, error) {
	// validate call input
	input, err := validateCallInput(params)
	if err != nil {
		return nil, err
	}

	// ensure valid contract address
	_, ok := ChecksumAddress(input.To)
	if !ok {
		return nil, ErrCallParametersInvalid
	}

	// ensure valid from address
	_, ok = ChecksumAddress(input.From)
	if !ok {
		return nil, ErrCallParametersInvalid
	}

	// parameters for eth_estimateGas
	estimateGasParams := map[string]string{
		"from": input.From,
		"to":   input.To,
		"data": input.Data,
	}

	var resp string
	if err := ec.c.CallContext(ctx, &resp, "eth_estimateGas", estimateGasParams); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data": resp,
	}, nil
}

func validateCallInput(params map[string]interface{}) (*GetCallInput, error) {
	var input GetCallInput
	if err := RosettaTypes.UnmarshalMap(params, &input); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
	}

	// to address is required for call requests
	if len(input.To) == 0 {
		return nil, fmt.Errorf("%w:to address is missing from parameters", ErrCallParametersInvalid)
	}

	if len(input.Data) == 0 {
		return nil, fmt.Errorf("%w:data is missing from parameters", ErrCallParametersInvalid)
	}
	return &input, nil
}

func convertTime(time uint64) int64 {
	return int64(time) * 1000
}

type rpcProgress struct {
	StartingBlock hexutil.Uint64
	CurrentBlock  hexutil.Uint64
	HighestBlock  hexutil.Uint64
	PulledStates  hexutil.Uint64
	KnownStates   hexutil.Uint64
}

type graphqlBalance struct {
	Errors []struct {
		Message string   `json:"message"`
		Path    []string `json:"path"`
	} `json:"errors"`
	Data struct {
		Block struct {
			Hash    string `json:"hash"`
			Number  int64  `json:"number"`
			Account struct {
				Balance string `json:"balance"`
				Nonce   string `json:"transactionCount"`
				Code    string `json:"code"`
			} `json:"account"`
		} `json:"block"`
	} `json:"data"`
}

// decodeHexData accepts a fully formed hex string (including the 0x prefix) and returns a big.Int
func decodeHexData(data string) (*big.Int, error) {
	decoded, ok := new(big.Int).SetString(data[2:], 16)
	if !ok {
		return nil, fmt.Errorf("could not extract data from %s", data)
	}
	return decoded, nil
}

// Balance returns the balance of a *RosettaTypes.AccountIdentifier
// at a *RosettaTypes.PartialBlockIdentifier.
// The OP Token and ETH balances will be returned if currencies is unspecified
//
//nolint:gocognit
func (ec *Client) Balance(
	ctx context.Context,
	account *RosettaTypes.AccountIdentifier,
	block *RosettaTypes.PartialBlockIdentifier,
	currencies []*RosettaTypes.Currency,
) (*RosettaTypes.AccountBalanceResponse, error) {
	var raw json.RawMessage
	if block != nil {
		if block.Hash != nil {
			if err := ec.c.CallContext(ctx, &raw, "eth_getBlockByHash", block.Hash, false); err != nil {
				return nil, err
			}
		}
		if block.Hash == nil && block.Index != nil {
			if err := ec.c.CallContext(
				ctx,
				&raw,
				"eth_getBlockByNumber",
				hexutil.EncodeUint64(uint64(*block.Index)),
				false,
			); err != nil {
				return nil, err
			}
		}
	} else {
		if err := ec.c.CallContext(ctx, &raw, "eth_getBlockByNumber", toBlockNumArg(nil), false); err != nil {
			return nil, err
		}
	}
	if len(raw) == 0 {
		return nil, ethereum.NotFound
	}

	var head *types.Header
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}

	var (
		balance hexutil.Big
		nonce   hexutil.Uint64
		code    string
	)

	blockNum := hexutil.EncodeUint64(head.Number.Uint64())
	reqs := []rpc.BatchElem{
		{Method: "eth_getBalance", Args: []interface{}{account.Address, blockNum}, Result: &balance},
		{Method: "eth_getTransactionCount", Args: []interface{}{account.Address, blockNum}, Result: &nonce},
		{Method: "eth_getCode", Args: []interface{}{account.Address, blockNum}, Result: &code},
	}
	if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
		return nil, err
	}
	for i := range reqs {
		if reqs[i].Error != nil {
			return nil, reqs[i].Error
		}
	}

	nativeBalance := &RosettaTypes.Amount{
		Value:    balance.ToInt().String(),
		Currency: Currency,
	}

	var balances []*RosettaTypes.Amount
	for _, curr := range currencies {
		if reflect.DeepEqual(curr, Currency) {
			balances = append(balances, nativeBalance)
			continue
		}

		contractAddress := fmt.Sprintf("%s", curr.Metadata[ContractAddressKey])
		_, ok := ChecksumAddress(contractAddress)
		if !ok {
			return nil, fmt.Errorf("invalid contract address %s", contractAddress)
		}

		balance, err := ec.getBalance(ctx, account.Address, blockNum, contractAddress)
		if err != nil {
			return nil, fmt.Errorf("err encountered for currency %s, token address %s; %v", curr.Symbol, contractAddress, err)
		}
		balances = append(balances, &RosettaTypes.Amount{
			Value:    balance,
			Currency: curr,
		})
	}

	if len(currencies) == 0 {
		opTokenBalance, err := ec.getBalance(ctx, account.Address, blockNum, opTokenContractAddress.String())
		if err != nil {
			return nil, fmt.Errorf("err getting OP token balance; %v", err)
		}
		balances = append(balances, nativeBalance, &RosettaTypes.Amount{
			Value:    opTokenBalance,
			Currency: OPTokenCurrency,
		})
	}

	return &RosettaTypes.AccountBalanceResponse{
		Balances: balances,
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  head.Hash().Hex(),
			Index: head.Number.Int64(),
		},
		Metadata: map[string]interface{}{
			"nonce": int64(nonce),
			"code":  code,
		},
	}, nil
}

func (ec *Client) getBalance(ctx context.Context, accountAddress string, blockNum string, contractAddress string) (string, error) {
	erc20Data, err := artifacts.ERC20ABI.Pack("balanceOf", common.HexToAddress(accountAddress))
	if err != nil {
		return "", err
	}
	encodedERC20Data := hexutil.Encode(erc20Data)

	callParams := map[string]string{
		"to":   contractAddress,
		"data": encodedERC20Data,
	}
	var resp string
	if err := ec.c.CallContext(ctx, &resp, "eth_call", callParams, blockNum); err != nil {
		return "", err
	}
	balance, err := decodeHexData(resp)
	if err != nil {
		return "", err
	}

	return balance.String(), nil
}

// GetBlockByNumberInput is the input to the call
// method "eth_getBlockByNumber".
type GetBlockByNumberInput struct {
	Index         *int64 `json:"index,omitempty"`
	ShowTxDetails bool   `json:"show_transaction_details"`
}

// GetTransactionReceiptInput is the input to the call
// method "eth_getTransactionReceipt".
type GetTransactionReceiptInput struct {
	TxHash string `json:"tx_hash"`
}

// GetCallInput is the input to the call
// method "eth_call", "eth_estimateGas".
type GetCallInput struct {
	BlockIndex int64  `json:"index,omitempty"`
	BlockHash  string `json:"hash,omitempty"`
	From       string `json:"from"`
	To         string `json:"to"`
	Gas        int64  `json:"gas"`
	GasPrice   int64  `json:"gas_price"`
	Value      int64  `json:"value"`
	Data       string `json:"data"`
}

// Call handles calls to the /call endpoint.
func (ec *Client) Call(
	ctx context.Context,
	request *RosettaTypes.CallRequest,
) (*RosettaTypes.CallResponse, error) {
	switch request.Method { // nolint:gocritic
	case EthGetBlockByNumber:
		var input GetBlockByNumberInput
		if err := RosettaTypes.UnmarshalMap(request.Parameters, &input); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
		}

		res, err := ec.blockByNumber(ctx, input.Index, input.ShowTxDetails)
		if err != nil {
			return nil, err
		}

		return &RosettaTypes.CallResponse{
			Result: res,
		}, nil
	case EthGetTransactionReceipt:
		var input GetTransactionReceiptInput
		if err := RosettaTypes.UnmarshalMap(request.Parameters, &input); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
		}

		if len(input.TxHash) == 0 {
			return nil, fmt.Errorf("%w:tx_hash missing from params", ErrCallParametersInvalid)
		}

		receipt, err := ec.transactionReceipt(ctx, common.HexToHash(input.TxHash))
		if err != nil {
			return nil, err
		}

		// We cannot use RosettaTypes.MarshalMap because geth uses a custom
		// marshaler to convert *types.Receipt to JSON.
		jsonOutput, err := receipt.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallOutputMarshal, err.Error())
		}

		var receiptMap map[string]interface{}
		if err := json.Unmarshal(jsonOutput, &receiptMap); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallOutputMarshal, err.Error())
		}

		// We must encode data over the wire so we can unmarshal correctly
		return &RosettaTypes.CallResponse{
			Result: receiptMap,
		}, nil
	case EthCall:
		resp, err := ec.contractCall(ctx, request.Parameters)
		if err != nil {
			return nil, err
		}

		return &RosettaTypes.CallResponse{
			Result: resp,
		}, nil
	case EthEstimateGas:
		resp, err := ec.estimateGas(ctx, request.Parameters)
		if err != nil {
			return nil, err
		}

		return &RosettaTypes.CallResponse{
			Result: resp,
		}, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrCallMethodInvalid, request.Method)
}
