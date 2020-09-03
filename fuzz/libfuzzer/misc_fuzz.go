package libfuzzer

import (
	"bytes"

	ffi "github.com/filecoin-project/filecoin-ffi"
	mock "github.com/filecoin-project/sector-storage/mock"
	gfuzz "github.com/google/gofuzz"

	//abi "github.com/filecoin-project/specs-actors/actors/abi"
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

func FuzzMockSectorMgr(data []byte) int {
	out := mock.SectorMgr{}
	f := gfuzz.NewFromGoFuzz(data).NilChance(0)
	f.Fuzz(&out)
	_ = out.SectorSize()
	_, err := out.AcquireSectorNumber()
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
