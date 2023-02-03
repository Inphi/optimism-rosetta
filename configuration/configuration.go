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

package configuration

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/inphi/optimism-rosetta/optimism"

	"github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum-optimism/optimism/l2geth/params"
)

// Mode is the setting that determines if
// the implementation is "online" or "offline".
type Mode string

const (
	// Online is when the implementation is permitted
	// to make outbound connections.
	Online Mode = "ONLINE"

	// Offline is when the implementation is not permitted
	// to make outbound connections.
	Offline Mode = "OFFLINE"

	// Mainnet is the Ethereum Mainnet.
	Mainnet string = "MAINNET"

	// Goerli is the Ethereum Görli testnet.
	Goerli string = "GOERLI"

	// Testnet defaults to `Ropsten` for backwards compatibility (even though we don't have a ropsten network on Optimism).
	Testnet string = "TESTNET"

	// DataDirectory is the default location for all
	// persistent data.
	DataDirectory = "/data"

	// ModeEnv is the environment variable read
	// to determine mode.
	ModeEnv = "MODE"

	// NetworkEnv is the environment variable
	// read to determine network.
	NetworkEnv = "NETWORK"

	// PortEnv is the environment variable
	// read to determine the port for the Rosetta
	// implementation.
	PortEnv = "PORT"

	// GethEnv is an optional environment variable
	// used to connect rosetta-ethereum to an already
	// running geth node.
	GethEnv = "GETH"

	// DefaultGethURL is the default URL for
	// a running geth node. This is used
	// when GethEnv is not populated.
	DefaultGethURL = "http://localhost:8545"

	// Tiemout of L2 Geth HTTP Client in seconds
	L2GethHTTPTimeoutEnv = "L2_GETH_HTTP_TIMEOUT"

	// Maximum number of concurrent debug_trace RPCs issued to nodes
	// debug tracing is an expensive operation that can DoS a node
	// if one is not careful
	MaxConcurrentTracesEnv = "MAX_CONCURRENT_TRACES"

	// MiddlewareVersion is the version of rosetta-ethereum.
	MiddlewareVersion = "0.0.4"

	// Experimental: Maintain a cache of debug traces
	EnableTraceCacheEnv = "ENABLE_TRACE_CACHE"

	// Experimental: Use newly added built-in geth tracer
	EnableGethTracer = "ENABLE_GETH_TRACER"

	// TokenFilterEnv is the environment variable
	// read to determine if we will filter tokens
	// using our token white list
	TokenFilterEnv = "FILTER_TOKEN"
)

// Configuration determines how
type Configuration struct {
	Mode                   Mode
	Network                *types.NetworkIdentifier
	GenesisBlockIdentifier *types.BlockIdentifier
	GethURL                string
	RemoteGeth             bool
	Port                   int
	GethArguments          string
	L2GethHTTPTimeout      time.Duration
	MaxConcurrentTraces    int64
	EnableTraceCache       bool
	EnableGethTracer       bool
	TokenFilter            bool
	SupportsSyncing        bool

	// Block Reward Data
	Params *params.ChainConfig
}

// LoadConfiguration attempts to create a new Configuration
// using the ENVs in the environment.
func LoadConfiguration() (*Configuration, error) {
	config := &Configuration{}

	modeValue := Mode(os.Getenv(ModeEnv))
	switch modeValue {
	case Online:
		config.Mode = Online
	case Offline:
		config.Mode = Offline
	case "":
		return nil, errors.New("MODE must be populated")
	default:
		return nil, fmt.Errorf("%s is not a valid mode", modeValue)
	}

	networkValue := os.Getenv(NetworkEnv)
	switch networkValue {
	case Mainnet:
		config.Network = &types.NetworkIdentifier{
			Blockchain: optimism.Blockchain,
			Network:    optimism.MainnetNetwork,
		}
		config.GenesisBlockIdentifier = optimism.MainnetGenesisBlockIdentifier
		config.Params = params.MainnetChainConfig
		config.Params.ChainID = big.NewInt(10) // TODO: temporary fix without param update
		config.GethArguments = optimism.MainnetGethArguments
	case Testnet: // goerli
		config.Network = &types.NetworkIdentifier{
			Blockchain: optimism.Blockchain,
			Network:    optimism.TestnetNetwork,
		}
		config.GenesisBlockIdentifier = optimism.TestnetGenesisBlockIdentifier
		config.Params = params.TestnetChainConfig
		config.Params.ChainID = big.NewInt(420) // TODO: temporary fix without param update
		config.GethArguments = optimism.TestnetGethArguments
	case Goerli:
		config.Network = &types.NetworkIdentifier{
			Blockchain: optimism.Blockchain,
			Network:    optimism.GoerliNetwork,
		}
		config.GenesisBlockIdentifier = optimism.GoerliGenesisBlockIdentifier
		config.Params = params.GoerliChainConfig
		config.GethArguments = optimism.GoerliGethArguments
	case "":
		return nil, errors.New("NETWORK must be populated")
	default:
		return nil, fmt.Errorf("%s is not a valid network", networkValue)
	}

	config.GethURL = DefaultGethURL
	envGethURL := os.Getenv(GethEnv)
	if len(envGethURL) > 0 {
		config.RemoteGeth = true
		config.GethURL = envGethURL
	}

	envL2GethHTTPTimeout := os.Getenv(L2GethHTTPTimeoutEnv)
	if len(envL2GethHTTPTimeout) > 0 {
		val, err := strconv.Atoi(envL2GethHTTPTimeout)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to parse L2_GETH_HTTP_TIMEOUT %s", err, envL2GethHTTPTimeout)
		}
		config.L2GethHTTPTimeout = time.Second * time.Duration(val)
	}

	envMaxConcurrentTraces := os.Getenv(MaxConcurrentTracesEnv)
	if len(envMaxConcurrentTraces) > 0 {
		val, err := strconv.Atoi(envMaxConcurrentTraces)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to parse %s envar %s", err, MaxConcurrentTracesEnv, envMaxConcurrentTraces)
		}
		config.MaxConcurrentTraces = int64(val)
	}

	portValue := os.Getenv(PortEnv)
	if len(portValue) == 0 {
		return nil, errors.New("PORT must be populated")
	}

	port, err := strconv.Atoi(portValue)
	if err != nil || len(portValue) == 0 || port <= 0 {
		return nil, fmt.Errorf("%w: unable to parse port %s", err, portValue)
	}
	config.Port = port

	envEnableTraceCache := os.Getenv(EnableTraceCacheEnv)
	if len(envEnableTraceCache) > 0 {
		val, err := strconv.ParseBool(envEnableTraceCache)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to parse %s %s", err, EnableTraceCacheEnv, envEnableTraceCache)
		}
		config.EnableTraceCache = val
	}

	envEnableGethTracer := os.Getenv(EnableGethTracer)
	if len(envEnableGethTracer) > 0 {
		val, err := strconv.ParseBool(envEnableGethTracer)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to parse %s %s", err, EnableGethTracer, envEnableGethTracer)
		}
		config.EnableGethTracer = val
	}

	config.TokenFilter = true
	envTokenFilter := os.Getenv(TokenFilterEnv)
	if len(envTokenFilter) > 0 {
		val, err := strconv.ParseBool(envTokenFilter)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to parse %s %s", err, TokenFilterEnv, envTokenFilter)
		}
		config.TokenFilter = val
	}

	return config, nil
}
