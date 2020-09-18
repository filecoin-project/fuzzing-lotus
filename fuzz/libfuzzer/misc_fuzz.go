package libfuzzer

import (
	"bytes"
	"fmt"
	"github.com/filecoin-project/lotus/paychmgr"
	"github.com/filecoin-project/go-address"
	ffi "github.com/filecoin-project/filecoin-ffi"
	"github.com/ipfs/go-cid"
	graphmessage "github.com/ipfs/go-graphsync/message"
)

// Fuzzing SortedPublicSectorInfo unmarshal/marshal from raw byteslice
func FuzzSortedPublicSectorInfoRaw(data []byte) int {
	out := ffi.SortedPublicSectorInfo{}
	err := out.UnmarshalJSON(data)
	if err != nil {
		return 0
	}
	return 1
}

// Fuzzing SortedPrivateSectorInfo unmarshal/marshal from raw byteslice
func FuzzSortedPrivateSectorInfoRaw(data []byte) int {
	out := ffi.SortedPublicSectorInfo{}
	err := out.UnmarshalJSON(data)
	if err != nil {
		return 0
	}
	return 1
}

func FuzzMockFromNet(data []byte) int {
	// out := graphmessage.SectorMgr{}
	read := bytes.NewReader(data)
	out, err := graphmessage.FromNet(read)
	if err != nil {
		return 0
	}
	_, err = out.ToProto()
	if err != nil {
		return 0
	}
	_ = out.Empty()
	_ = out.Requests()  // listGraphSyncRequest
	_ = out.Responses() // listGraphSyncResponse
	_ = out.Blocks()    // listBlocks
	return 1
}

// Fuzzing ChannelInfo unmarshal/marshal from raw byteslice
func FuzzChannelInfo(data []byte) int {
	var channel paychmgr.ChannelInfo
	if err := channel.UnmarshalCBOR(bytes.NewReader(data)); err != nil {
		return 0
	}
	// Note: should use unmarshallChannelInfo() but that is private
	var emptyAddr address.Address
	if channel.Channel != nil && *channel.Channel == emptyAddr {
		channel.Channel = nil
	}


	buf := new(bytes.Buffer)
	if err := channel.MarshalCBOR(buf); err != nil {
		panic(fmt.Sprintf("Error in serializing ChannelInfo: %v", err))
	}
	encoded := buf.Bytes()

	// Checks if the encoded message is different to the fuzz data.
	if !bytes.Equal(encoded, data[:len(encoded)]) {
			panic(fmt.Sprintf("Fuzz data and serialized data are not equal: %v vs %v", encoded, data))
	}
	return 1
}

// Parsing CID
func FuzzCID(data []byte) int {
	cid.Parse(string(data))
	return 1
}
