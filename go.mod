module github.com/sigp/lotus-review

go 1.14

replace github.com/supranational/blst => ./code/deps/blst

replace github.com/filecoin-project/go-fil-markets => ./code/go-fil-markets

replace github.com/filecoin-project/lotus => ./code/lotus

replace github.com/filecoin-project/filecoin-ffi => ./code/lotus/extern/filecoin-ffi

replace github.com/filecoin-project/specs-actors => ./code/specs-actors

// These are only really needed if we make patches or changes to the module
// Otherwise, these should be equivalent to what's depended on by ./code/lotus
replace github.com/filecoin-project/go-address => ./code/deps/go-address

replace github.com/filecoin-project/go-amt-ipld => ./code/deps/go-amt-ipld

replace github.com/filecoin-project/go-bitfield => ./code/deps/go-bitfield

replace github.com/filecoin-project/go-cbor-util => ./code/deps/go-cbor-util

replace github.com/filecoin-project/go-crypto => ./code/deps/go-crypto

replace github.com/filecoin-project/go-fil-commcid => ./code/deps/go-fil-commcid

replace github.com/filecoin-project/go-padreader => ./code/deps/go-padreader

replace github.com/filecoin-project/go-statemachine => ./code/deps/go-statemachine

replace github.com/filecoin-project/go-statestore => ./code/deps/go-statestore

replace github.com/filecoin-project/specs-storage => ./code/deps/specs-storage

replace github.com/ipfs/go-graphsync => ./code/deps/go-graphsync

replace github.com/ipfs/go-hamt-ipld => ./code/deps/go-hamt-ipld

replace github.com/ipfs/go-ipld-cbor => ./code/deps/go-ipld-cbor

replace github.com/whyrusleeping/cbor-gen => ./code/deps/cbor-gen

require (
	github.com/dchest/varuint v0.0.0-20160117093252-0a68758e1c21
	github.com/dvyukov/go-fuzz v0.0.0-20200318091601-be3528f3a813 // indirect
	github.com/dvyukov/go-fuzz-corpus v0.0.0-20190920191254-c42c1b2914c7
	github.com/elazarl/go-bindata-assetfs v1.0.0 // indirect
	github.com/filecoin-project/filecoin-ffi v0.30.4-0.20200716204036-cddc56607e1d
	github.com/filecoin-project/go-address v0.0.3
	github.com/filecoin-project/go-amt-ipld v1.0.0
	github.com/filecoin-project/go-bitfield v0.2.0
	github.com/filecoin-project/go-cbor-util v0.0.0-20191219014500-08c40a1e63a2
	github.com/filecoin-project/go-crypto v0.0.0-20191218222705-effae4ea9f03
	github.com/filecoin-project/go-data-transfer v0.6.3
	github.com/filecoin-project/go-fil-commcid v0.0.0-20200716160307-8f644712406f
	github.com/filecoin-project/go-fil-markets v0.5.8
	github.com/filecoin-project/go-padreader v0.0.0-20200210211231-548257017ca6
	github.com/filecoin-project/go-statemachine v0.0.0-20200813232949-df9b130df370
	github.com/filecoin-project/go-statestore v0.1.0
	github.com/filecoin-project/lotus v0.4.3-0.20200820203717-d1718369a182
	github.com/filecoin-project/specs-actors v0.9.3
	github.com/google/go-cmp v0.5.0
	github.com/google/gofuzz v1.1.1-0.20200604201612-c04b05f3adfa
	github.com/ipfs/go-cid v0.0.7
	github.com/ipfs/go-graphsync v0.1.2
	github.com/ipfs/go-hamt-ipld v0.1.1
	github.com/ipfs/go-ipld-cbor v0.0.5-0.20200428170625-a0bd04d3cbdf
	github.com/mdempsky/go114-fuzz-build v0.0.0-20200604085624-2fed56972255 // indirect
	github.com/multiformats/go-multihash v0.0.14
	github.com/stephens2424/writerset v1.0.2 // indirect
	github.com/stretchr/testify v1.6.1
	github.com/whyrusleeping/cbor-gen v0.0.0-20200814224545-656e08ce49ee
	golang.org/x/mod v0.3.0 // indirect
)
