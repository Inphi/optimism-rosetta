.PHONY: deps build run lint run-mainnet-online run-mainnet-offline run-testnet-online \
	run-testnet-offline check-comments add-license check-license shorten-lines \
	spellcheck salus build-local format check-format update-tracer test coverage coverage-local \
	update-bootstrap-balances mocks test tests format lint tidy

ADDLICENSE_INSTALL=go install github.com/google/addlicense@latest
ADDLICENSE_CMD=addlicense
ADDLICENCE_SCRIPT=${ADDLICENSE_CMD} -c "Coinbase, Inc." -l "apache" -v
SPELLCHECK_CMD=go run github.com/client9/misspell/cmd/misspell
SPELLCHECK_INSTALL=go mod download github.com/client9/misspell
GOLINES_INSTALL=go install github.com/segmentio/golines@latest
GOLINES_CMD=golines
GOVERALLS_INSTALL=go install github.com/mattn/goveralls@latest
GOVERALLS_CMD=goveralls
GOIMPORTS_INSTALL=go get golang.org/x/tools/cmd/goimports
GOIMPORTS_CMD=go run golang.org/x/tools/cmd/goimports
GO_PACKAGES=./services/... ./cmd/... ./configuration/... ./optimism/...
GO_FOLDERS=$(shell echo ${GO_PACKAGES} | sed -e "s/\.\///g" | sed -e "s/\/\.\.\.//g")
PWD=$(shell pwd)
NOFILE=100000

# This is left as rosetta-ethereum for backwards compatibility
OUTPUT_BIN=rosetta-ethereum

# Linting
LINT_INSTALL=go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.51.1
LINT_CMD=golangci-lint run
LINT_SETTINGS=golint,misspell,gocyclo,gocritic,whitespace,gocognit,bodyclose,unconvert,unparam

# Test Scripts
TEST_SCRIPT=go test ${GO_PACKAGES}

all: clean deps tidy format test spellcheck lint

clean:
	go clean

tidy:
	go mod tidy

deps:
	go get ./...

test:
	${TEST_SCRIPT}

lint:
	${LINT_INSTALL}
	golangci-lint run --timeout 2m0s -v -E ${LINT_SETTINGS}

##################################################################################
## GOERLI GOERLI GOERLI GOERLI GOERLI GOERLI GOERLI GOERLI GOERLI GOERLI GOERLI ##
##################################################################################

# Runs rosetta-cli configuration:validate against the optimism goerli configuration
run-optimism-goerli-validate-config:
	ROSETTA_CONFIGURATION_FILE=configs/optimism/goerli.json rosetta-cli configuration:validate configs/optimism/goerli.json

# Runs the rosetta-cli check:data command with the optimism goerli configuration
run-optimism-goerli-data-check:
	ROSETTA_CONFIGURATION_FILE=configs/optimism/goerli.json rosetta-cli check:data configs/optimism/goerli.json

# Runs the rosetta-cli check:construction command with the optimism goerli configuration
run-optimism-goerli-construction-check:
	ROSETTA_CONFIGURATION_FILE=configs/optimism/goerli.json rosetta-cli check:construction configs/optimism/goerli.json

# Runs an instance of `op-rosetta` configured for Optimism Goerli
# For the transition (aka "genesis") block hash, see:
# https://github.com/ethereum-optimism/optimism/blob/5e8bc3d5b4f36f0192b22b032e25b09f23cd0985/op-node/chaincfg/chains.go#L49
run-optimism-goerli:
	CHAIN_CONFIG='{ "chainId": 10, "terminalTotalDifficultyPassed": true }'	\
	MODE=ONLINE \
	PORT=8080 \
	BLOCKCHAIN=Optimism \
	NETWORK=Goerli \
	GETH=${OPTIMISM_GOERLI_NODE} \
	ENABLE_TRACE_CACHE=true \
    ENABLE_GETH_TRACER=true \
	TRANSITION_BLOCK_HASH=${OPTIMISM_GOERLI_TRANSITION_BLOCK_HASH} \
	${OUTPUT_BIN}

##################################################################################
##################################################################################

build:
	go build -v -o optimism-rosetta ./cmd/...

build-docker:
	docker build -t rosetta-ethereum:latest https://github.com/inphi/optimism-rosetta.git

build-local:
	docker build -t rosetta-ethereum:latest .

build-release:
	# make sure to always set version with vX.X.X
	docker build -t rosetta-ethereum:$(version) .;
	docker save rosetta-ethereum:$(version) | gzip > rosetta-ethereum-$(version).tar.gz;

update-tracer:
	curl https://raw.githubusercontent.com/ethereum/go-ethereum/master/eth/tracers/js/internal/tracers/call_tracer_js.js -o optimism/call_tracer.js

update-bootstrap-balances:
	go run main.go utils:generate-bootstrap https://storage.googleapis.com/optimism/mainnet/genesis-v0.5.0.json rosetta-cli-conf/mainnet/bootstrap_balances.json;
	go run main.go utils:generate-bootstrap https://storage.googleapis.com/optimism/kovan/v0.5.0-rc2.json rosetta-cli-conf/testnet/bootstrap_balances.json;

run-mainnet-online:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/ethereum-data:/data" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-ethereum:latest

run-mainnet-offline:
	docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=MAINNET" -e "PORT=8081" -p 8081:8081 rosetta-ethereum:latest

run-testnet-online:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -v "${PWD}/ethereum-data:/data" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -p 8080:8080 -p 30303:30303 rosetta-ethereum:latest

run-testnet-offline:
	docker run -d --rm -e "MODE=OFFLINE" -e "NETWORK=TESTNET" -e "PORT=8081" -p 8081:8081 rosetta-ethereum:latest

run-mainnet-remote:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -e "MODE=ONLINE" -e "NETWORK=MAINNET" -e "PORT=8080" -e "GETH=$(geth)" -p 8080:8080 -p 30303:30303 rosetta-ethereum:latest

run-testnet-remote:
	docker run -d --rm --ulimit "nofile=${NOFILE}:${NOFILE}" -e "MODE=ONLINE" -e "NETWORK=TESTNET" -e "PORT=8080" -e "GETH=$(geth)" -p 8080:8080 -p 30303:30303 rosetta-ethereum:latest

add-license:
	${ADDLICENSE_INSTALL}
	${ADDLICENCE_SCRIPT} .

check-license:
	${ADDLICENSE_INSTALL}
	${ADDLICENCE_SCRIPT} -check .

shorten-lines:
	${GOLINES_INSTALL}
	${GOLINES_CMD} -w --shorten-comments ${GO_FOLDERS} .

format:
	${GOIMPORTS_INSTALL}
	gofmt -s -w -l .
	${GOIMPORTS_CMD} -w .

check-format:
	! gofmt -s -l . | read
	! ${GOIMPORTS_CMD} -l . | read

salus:
	docker run --rm -t -v ${PWD}:/home/repo coinbase/salus

spellcheck: |
	${SPELLCHECK_INSTALL}
	${SPELLCHECK_CMD} -error .

coverage:
	${GOVERALLS_INSTALL}
	if [ "${COVERALLS_TOKEN}" ]; then ${TEST_SCRIPT} -coverprofile=c.out -covermode=count; ${GOVERALLS_CMD} -coverprofile=c.out -repotoken ${COVERALLS_TOKEN}; fi

coverage-local:
	${TEST_SCRIPT} -cover

mocks:
	rm -rf mocks;
	mockery --dir services --all --case underscore --outpkg services --output mocks/services;
	mockery --dir optimism --all --case underscore --outpkg optimism --output mocks/optimism;
	${ADDLICENSE_INSTALL}
	${ADDLICENCE_SCRIPT} .;

local_rosetta:
	NETWORK=MAINNET MODE=ONLINE PORT=3045 MAX_CONCURRENT_TRACES=12 ENABLE_GETH_TRACER=false ENABLE_TRACE_CACHE=false TRACE_BY_BLOCK=true GETH=https://c3-chainproxy-optimism-mainnet.cbhq.net:8545 ./optimism-rosetta run
