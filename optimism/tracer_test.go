package optimism

import (
	"context"
	"testing"
	"time"

	mocks "github.com/coinbase/rosetta-ethereum/mocks/optimism"
	"github.com/ethereum-optimism/optimism/l2geth/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestTracerFetch_HappyPath(t *testing.T) {
	ctx := context.Background()

	mockClient := &mocks.JSONRPC{}
	cache, err := NewTraceCache(mockClient, "call_tracer.js", time.Second*1, 10)
	assert.NoError(t, err)

	expect := Call{Type: "ekans"}
	mockClient.On(
		"CallContext",
		mock.Anything,
		mock.Anything,
		"debug_traceTransaction",
		mock.Anything,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*Call)
			*r = expect
		},
	).Once()

	call, err := cache.FetchTransaction(ctx, common.Hash{})
	assert.NoError(t, err)
	assert.Equal(t, expect, *call)
}

func TestTracerFetch_ExpiredContext(t *testing.T) {
	ctx := context.Background()

	mockClient := &mocks.JSONRPC{}
	cache, err := NewTraceCache(mockClient, "call_tracer.js", time.Second*1, 10)
	assert.NoError(t, err)

	expect := Call{Type: "ekans"}
	mockClient.On(
		"CallContext",
		mock.Anything,
		mock.Anything,
		"debug_traceTransaction",
		mock.Anything,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			time.Sleep(time.Millisecond * 500)
			r := args.Get(1).(*Call)
			*r = expect
		},
	).Once()

	ctx, cancel := context.WithTimeout(ctx, time.Millisecond*1)
	_, err = cache.FetchTransaction(ctx, common.Hash{})
	cancel()
	assert.EqualError(t, err, context.DeadlineExceeded.Error())

	// The JSONRPC is mocked only once so the second call reads existing value from the cache
	call, err := cache.FetchTransaction(context.Background(), common.Hash{})
	assert.NoError(t, err)
	assert.Equal(t, expect, *call)
}
