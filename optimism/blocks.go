package optimism

import "math/big"

type BlockParser struct {
	bedrockBlock *big.Int
}

func NewBlockParser(bedrockBlock *big.Int) *BlockParser {
	return &BlockParser{
		bedrockBlock: bedrockBlock,
	}
}
