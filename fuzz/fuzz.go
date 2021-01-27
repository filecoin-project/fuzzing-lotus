package fuzz

import (
	"bytes"
	"fmt"
	"github.com/filecoin-project/go-address"
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
	if !bytes.Equal(encodedMsg, data[:len(encodedMsg)]) {
			panic("Fuzz data and serialized data are not equal")
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
	if !cmp.Equal(&blockmsg, msg) {
		panic("Fuzz data and serialized data are not equal")
	}
	return 1
}

// Fuzzes Address.
func FuzzAddress(data []byte) int {
	var addr address.Address
	if err := addr.UnmarshalCBOR(bytes.NewReader(data)); err != nil {
		return 0
	}

	buf := new(bytes.Buffer)
	if err := addr.MarshalCBOR(buf); err != nil {
		panic(fmt.Sprintf("Error in serializing Address: %v", err))
	}
	encoded := buf.Bytes()
	// Checks if the encoded message is different to the fuzz data.
	if !bytes.Equal(encoded, data[:len(encoded)]) {
			panic("Fuzz data and serialized data are not equal")
	}
	return 1
}

// Fuzzes BigInt.
func FuzzBigInt(data []byte) int {
	var bigInt types.BigInt
	if err := bigInt.UnmarshalCBOR(bytes.NewReader(data)); err != nil {
		return 0
	}

	buf := new(bytes.Buffer)
	if err := bigInt.MarshalCBOR(buf); err != nil {
		panic(fmt.Sprintf("Error in serializing BigInt: %v", err))
	}
	encoded := buf.Bytes()
	// Checks if the encoded message is different to the fuzz data.
	if !bytes.Equal(encoded, data[:len(encoded)]) {
			panic("Fuzz data and serialized data are not equal")
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
		panic("Fuzz data and serialized data are not equal")
	}

	// Checks if the decoded BlockHeader is different to the initial BlockHeader.
	if !cmp.Equal(blockheader, &header) {
		panic(fmt.Sprintf("Decoded BlockHeader and serialized BlockHeader are not equal: %v vs %v", blockheader, &header))
	}
	return 1
}
