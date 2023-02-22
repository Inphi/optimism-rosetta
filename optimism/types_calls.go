package optimism

import (
	"encoding/json"
	"math/big"

	EthCommon "github.com/ethereum/go-ethereum/common"
	EthHexUtil "github.com/ethereum/go-ethereum/common/hexutil"
)

// Call is an Ethereum debug trace.
type Call struct {
	Type         string            `json:"type"`
	From         EthCommon.Address `json:"from"`
	To           EthCommon.Address `json:"to"`
	Value        *big.Int          `json:"value"`
	GasUsed      *big.Int          `json:"gasUsed"`
	Input        string            `json:"input"`
	Revert       bool
	ErrorMessage string  `json:"error"`
	Calls        []*Call `json:"calls"`
}

// FlatCall is a flattened [Call] object.
type FlatCall struct {
	Type         string            `json:"type"`
	From         EthCommon.Address `json:"from"`
	To           EthCommon.Address `json:"to"`
	Value        *big.Int          `json:"value"`
	GasUsed      *big.Int          `json:"gasUsed"`
	Input        string            `json:"input"`
	Revert       bool
	ErrorMessage string `json:"error"`
}

func (t *Call) flatten() *FlatCall {
	return &FlatCall{
		Type:         t.Type,
		From:         t.From,
		To:           t.To,
		Value:        t.Value,
		GasUsed:      t.GasUsed,
		Input:        t.Input,
		Revert:       t.Revert,
		ErrorMessage: t.ErrorMessage,
	}
}

// UnmarshalJSON is a custom unmarshaler for Call.
func (t *Call) UnmarshalJSON(input []byte) error {
	type CustomTrace struct {
		Type         string            `json:"type"`
		From         EthCommon.Address `json:"from"`
		To           EthCommon.Address `json:"to"`
		Value        *EthHexUtil.Big   `json:"value"`
		GasUsed      *EthHexUtil.Big   `json:"gasUsed"`
		Input        string            `json:"input"`
		Revert       bool
		ErrorMessage string  `json:"error"`
		Calls        []*Call `json:"calls"`
	}
	var dec CustomTrace
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}

	t.Type = dec.Type
	t.From = dec.From
	t.To = dec.To
	if dec.Value != nil {
		t.Value = (*big.Int)(dec.Value)
	} else {
		t.Value = new(big.Int)
	}
	if dec.GasUsed != nil {
		t.GasUsed = (*big.Int)(dec.GasUsed)
	} else {
		t.GasUsed = new(big.Int)
	}
	t.Input = dec.Input
	if dec.ErrorMessage != "" {
		// Any error surfaced by the decoder means that the transaction
		// has reverted.
		t.Revert = true
	}
	t.ErrorMessage = dec.ErrorMessage
	t.Calls = dec.Calls
	return nil
}

// flattenTraces recursively flattens all traces.
func flattenTraces(data *Call, flattened []*FlatCall) []*FlatCall {
	//nolint:gocritic
	results := append(flattened, data.flatten())
	for _, child := range data.Calls {
		// Ensure all children of a reverted call
		// are also reverted!
		if data.Revert {
			child.Revert = true

			// Copy error message from parent
			// if child does not have one
			if len(child.ErrorMessage) == 0 {
				child.ErrorMessage = data.ErrorMessage
			}
		}

		children := flattenTraces(child, flattened)
		results = append(results, children...)
	}
	return results
}
