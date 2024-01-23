package optimism

import (
	"os"

	mocks "github.com/inphi/optimism-rosetta/mocks/optimism"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mocking interface {
	MockJSONRPC() *mocks.JSONRPC
	NoError(error error, msgAndArgs ...interface{}) bool
}

type simpleMocking struct {
	m          *mocks.JSONRPC
	assertions *assert.Assertions
}

func (m *simpleMocking) MockJSONRPC() *mocks.JSONRPC {
	return m.m
}

func (m *simpleMocking) NoError(err error, msgAndArgs ...interface{}) bool {
	return m.assertions.NoError(err, msgAndArgs...)
}

func mockTraceTransaction(ctx interface{}, m mocking, txFileData string, rpcArgs ...interface{}) {
	rpc := m.MockJSONRPC()
	args := []interface{}{ctx, mock.Anything, "debug_traceTransaction"}
	args = append(args, rpcArgs...)
	if len(rpcArgs) == 0 {
		args = append(args, mock.Anything, mock.Anything)
	} else if len(rpcArgs) == 1 {
		args = append(args, mock.Anything)
	}

	rpc.On("CallContext", args...).Return(nil).Run(
		func(args mock.Arguments) {
			r := args.Get(1).(**Call)
			file, err := os.ReadFile(txFileData)
			m.NoError(err)
			call := new(Call)
			m.NoError(call.UnmarshalJSON(file))
			*r = call
		},
	).Once()
}
