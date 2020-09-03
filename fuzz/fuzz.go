package fuzz

import (
	"bytes"
	"fmt"

	"github.com/filecoin-project/lotus/chain/types"
	"github.com/google/go-cmp/cmp"
	gfuzz "github.com/google/gofuzz"
)

// Fuzzes DecodeBlockMsg using random data
func FuzzBlockMsg(data []byte) int {

	msg, err := types.DecodeBlockMsg(data)
	if err != nil {
		return 0
	}
	encodedMsg, err := msg.Serialize()
	if err != nil {
		panic(fmt.Sprintf("Error in serializing BlockMsg: %v", err))
	}
	// Checks if the encoded message is different to the fuzz data.
	if !bytes.Equal(encodedMsg, data) {
		panic(fmt.Sprintf("Fuzz data and serialized data are not equal: %v", err))
	}
	return 1
}

// Structural fuzzing on the BlockMsg struct to provide valid binary data.
func FuzzBlockMsgStructural(data []byte) int {

	blockmsg := types.BlockMsg{}
	f := gfuzz.NewFromGoFuzz(data).NilChance(0)
	f.Fuzz(&blockmsg)
	encodedMsg, err := blockmsg.Serialize()
	if err != nil {
		return 0
	}
	msg, err := types.DecodeBlockMsg(encodedMsg)
	if err != nil {
		panic(fmt.Sprintf("Error in decoding BlockMsg: %v", err))
	}

	// Checks if the decoded message is different to the initial blockmsg.
	if !cmp.Equal(blockmsg, msg) {
		panic(fmt.Sprintf("Decoded BlockMsg and serialized BlockMsg are not equal: %v", err))
	}
	return 1
}

// Fuzzes DecodeBlock function for a given BlockHeader.
func FuzzBlockHeader(data []byte) int {

	blockheader := types.BlockHeader{}
	f := gfuzz.NewFromGoFuzz(data).NilChance(0)
	f.Fuzz(&blockheader)
	encodedHeader, err := blockheader.Serialize()
	if err != nil {
		return 0
	}
	header, err := types.DecodeBlock(encodedHeader)
	if err != nil {
		panic(fmt.Sprintf("Error in decoding BlockHeader: %v", err))
	}

	// Checks if the decoded BlockHeader is different to the initial BlockHeader.
	if !cmp.Equal(blockheader, header) {
		panic(fmt.Sprintf("Decoded BlockHeader and serialized BlockHeader are not equal: %v", err))
	}
	return 1
}
