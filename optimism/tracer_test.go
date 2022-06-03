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
	tspec := tracerSpec{TracerPath: "call_tracer.js"}
	cache, err := NewTraceCache(mockClient, tspec, time.Second*1, 10)
	assert.NoError(t, err)

	tc, err := loadTraceConfig(tspec, time.Second*1)
	assert.NoError(t, err)
	hash := common.HexToHash("0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a")

	expect := Call{Type: "ekans"}
	mockClient.On(
		"CallContext",
		mock.Anything,
		mock.Anything,
		"debug_traceTransaction",
		common.HexToHash("0x5e77a04531c7c107af1882d76cbff9486d0a9aa53701c30888509d4f5f2b003a").Hex(),
		tc,
	).Return(
		nil,
	).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(*Call)
			*r = expect
		},
	).Once()

	call, err := cache.FetchTransaction(ctx, hash)
	assert.NoError(t, err)
	assert.Equal(t, expect, *call)
}

func TestTracerFetch_ExpiredContext(t *testing.T) {
	ctx := context.Background()

	mockClient := &mocks.JSONRPC{}
	tspec := tracerSpec{TracerPath: "call_tracer.js"}
	cache, err := NewTraceCache(mockClient, tspec, time.Second*1, 10)
	assert.NoError(t, err)

	expect := Call{Type: "ekans"}
	mockClient.On(
		"CallContext",
		mock.Anything,
		mock.Anything,
		"debug_traceTransaction",
		mock.Anything,
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
