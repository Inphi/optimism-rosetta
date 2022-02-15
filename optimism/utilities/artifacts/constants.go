// Copyright 2021 Coinbase, Inc.
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

package artifacts

import (
	_ "embed" // lint note: embed is to be used implicitly, and thus the wildcard is needed
	"log"
	"strings"

    "github.com/ethereum/go-ethereum/accounts/abi"
)

//go:embed abi/ERC20.abi
var erc20ABIString string

var (
	ERC20ABI = mustParse(erc20ABIString)
)

func mustParse(str string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(str))
	if err != nil {
		log.Panic(err)
	}

	return parsed
}
