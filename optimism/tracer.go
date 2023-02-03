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
	"io/ioutil"
	"sync"
	"time"

	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/ethereum-optimism/optimism/l2geth/eth"
	lru "github.com/hashicorp/golang-lru"
)

// convert raw eth data from client to rosetta

const (
	defaultTracerPath = "optimism/call_tracer.js"
)

type tracerSpec struct {
	TracerPath    string
	UseGethTracer bool
}

func loadTraceConfig(opt tracerSpec, timeout time.Duration) (*eth.TraceConfig, error) {
	var loadedTracer string
	if opt.UseGethTracer {
		loadedTracer = "rosetta"
	} else {
		loadedFile, err := ioutil.ReadFile(opt.TracerPath)
		if err != nil {
			return nil, fmt.Errorf("%w: could not load tracer file", err)
		}
		loadedTracer = string(loadedFile)
	}
	tracerTimeout := fmt.Sprintf("%ds", int(timeout.Seconds()))
	return &eth.TraceConfig{
		Timeout: &tracerTimeout,
		Tracer:  &loadedTracer,
	}, nil
}

type traceCacheEntry struct {
	pending chan struct{}
	result  *Call
	err     error
}

type TraceCache interface {
	FetchTransaction(ctx context.Context, txhash common.Hash) (*Call, error)
}

type traceCache struct {
	client        JSONRPC
	tc            *eth.TraceConfig
	tracerTimeout time.Duration
	cache         *lru.Cache
	m             sync.Mutex
}

func NewTraceCache(client JSONRPC, opt tracerSpec, tracerTimeout time.Duration, cacheSize int) (TraceCache, error) {
	cache, _ := lru.New(cacheSize)
	tc, err := loadTraceConfig(opt, tracerTimeout)
	if err != nil {
		return nil, err
	}

	return &traceCache{
		client:        client,
		tc:            tc,
		tracerTimeout: tracerTimeout,
		cache:         cache,
	}, nil
}

func (t *traceCache) FetchTransaction(ctx context.Context, txhash common.Hash) (*Call, error) {
	t.m.Lock()

	var entry *traceCacheEntry
	if lruEntry, ok := t.cache.Get(txhash.Hex()); ok {
		entry = lruEntry.(*traceCacheEntry)
	}

	if entry == nil {
		entry = &traceCacheEntry{make(chan struct{}), new(Call), nil}
		t.cache.Add(txhash.Hex(), entry)

		go t.requestTrace(txhash, entry)
	}

	t.m.Unlock()

	select {
	case <-entry.pending:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return entry.result, entry.err
}

func (t *traceCache) requestTrace(txhash common.Hash, entry *traceCacheEntry) {
	// tracer evm execution timeout + some additional time for I/O
	tracerTimeout := t.tracerTimeout + time.Second
	callCtx, cancel := context.WithTimeout(context.Background(), tracerTimeout)
	defer cancel()
	entry.err = t.client.CallContext(callCtx, entry.result, "debug_traceTransaction", txhash.Hex(), t.tc)

	close(entry.pending)

	if entry.err != nil {
		// It's fine if FetchTransaction calls read the old errant cache entry before it's removed
		t.m.Lock()
		t.cache.Remove(txhash.String())
		t.m.Unlock()
	}
}
