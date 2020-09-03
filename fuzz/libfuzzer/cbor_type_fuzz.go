// Contains fuzzing harnesses to be run with libfuzzer
// Usually because they reference some cgo symbols and can't be built with go-fuzz

package libfuzzer

import (
	"bytes"
	"fmt"
	"reflect"

	dfuzzutil "github.com/dvyukov/go-fuzz-corpus/fuzz"
	goaddr "github.com/filecoin-project/go-address"
	amtipld "github.com/filecoin-project/go-amt-ipld"
	"github.com/filecoin-project/go-fil-markets/retrievalmarket"
	statemachine "github.com/filecoin-project/go-statemachine"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/blocksync"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/node/hello"
	"github.com/filecoin-project/lotus/paychmgr"
	"github.com/filecoin-project/specs-actors/actors/builtin/cron"
	init_ "github.com/filecoin-project/specs-actors/actors/builtin/init"
	"github.com/filecoin-project/specs-actors/actors/builtin/market"
	"github.com/filecoin-project/specs-actors/actors/builtin/miner"
	"github.com/filecoin-project/specs-actors/actors/builtin/multisig"
	"github.com/filecoin-project/specs-actors/actors/builtin/paych"
	"github.com/filecoin-project/specs-actors/actors/builtin/power"
	"github.com/filecoin-project/specs-actors/actors/builtin/reward"
	"github.com/filecoin-project/specs-actors/actors/builtin/verifreg"
	"github.com/filecoin-project/specs-actors/actors/puppet"
	fsm "github.com/filecoin-project/storage-fsm"
	gfuzz "github.com/google/gofuzz"
	hamtipld "github.com/ipfs/go-hamt-ipld"

	cbg "github.com/whyrusleeping/cbor-gen"
)

// A type that has MarshalCBOR and UnmarshalCBOR methods
type CBORer interface {
	cbg.CBORMarshaler
	cbg.CBORUnmarshaler
}

// NOTE: there are other types left out here, because they are contained inside
// The best targets are ones whose corpora can easily be extracted from testnets etc.

// To save making the reflection type every time the harness is called
var cborTypeMap = map[string]reflect.Type{
	"BlockSyncRequest":  reflect.TypeOf((*blocksync.BlockSyncRequest)(nil)).Elem(),
	"BlockSyncResponse": reflect.TypeOf((*blocksync.BlockSyncResponse)(nil)).Elem(),
	"HelloMessage":      reflect.TypeOf((*hello.HelloMessage)(nil)).Elem(),
	"LatencyMessage":    reflect.TypeOf((*hello.LatencyMessage)(nil)).Elem(),
	"VoucherInfo":       reflect.TypeOf((*paychmgr.VoucherInfo)(nil)).Elem(),
	"ChannelInfo":       reflect.TypeOf((*paychmgr.ChannelInfo)(nil)).Elem(),
	"PaymentInfo":       reflect.TypeOf((*api.PaymentInfo)(nil)).Elem(),
	"SealedRef":         reflect.TypeOf((*api.SealedRef)(nil)).Elem(),
	"SealedRefs":        reflect.TypeOf((*api.SealedRefs)(nil)).Elem(),
	"SealTicket":        reflect.TypeOf((*api.SealTicket)(nil)).Elem(),
	"SealSeed":          reflect.TypeOf((*api.SealSeed)(nil)).Elem(),
	"Actor":             reflect.TypeOf((*types.Actor)(nil)).Elem(),
	"TipSet":            reflect.TypeOf((*types.TipSet)(nil)).Elem(),
	"SignedMessage":     reflect.TypeOf((*types.SignedMessage)(nil)).Elem(),
	"MsgMeta":           reflect.TypeOf((*types.MsgMeta)(nil)).Elem(),
	"MessageReceipt":    reflect.TypeOf((*types.MessageReceipt)(nil)).Elem(),
	"DealProposal":      reflect.TypeOf((*retrievalmarket.DealProposal)(nil)).Elem(),
	// patrick targets
	"SectorInfo":   reflect.TypeOf((*fsm.SectorInfo)(nil)).Elem(),
	"Piece":        reflect.TypeOf((*fsm.Piece)(nil)).Elem(),
	"DealSchedule": reflect.TypeOf((*fsm.DealSchedule)(nil)).Elem(),
	"DealInfo":     reflect.TypeOf((*fsm.DealInfo)(nil)).Elem(),
	"Address":      reflect.TypeOf((*goaddr.Address)(nil)).Elem(),
	"Deferred":     reflect.TypeOf((*cbg.Deferred)(nil)).Elem(),
	"KV":           reflect.TypeOf((*hamtipld.KV)(nil)).Elem(),
	"Node":         reflect.TypeOf((*hamtipld.Node)(nil)).Elem(),
	"Pointer":      reflect.TypeOf((*hamtipld.Pointer)(nil)).Elem(),
	"NodeAmt":      reflect.TypeOf((*amtipld.Node)(nil)).Elem(),
	"RootAmt":      reflect.TypeOf((*amtipld.Root)(nil)).Elem(),
	"TestEvent":    reflect.TypeOf((*statemachine.TestEvent)(nil)).Elem(),
	"TestState":    reflect.TypeOf((*statemachine.TestState)(nil)).Elem(),
	//TODO DataTransferMessage is an interface not a struct type, need to expose
	//the hidden `transferMessage` type
	//"DataTransferMessage":     reflect.TypeOf((*message.DataTransferMessage)(nil)).Elem(),
	//TODO remove? the following types don't implement CBORer
	//"SortedPublicSectorInfo":  reflect.TypeOf((*ffi.SortedPublicSectorInfo)(nil)).Elem(),
	//"SortedPrivateSectorInfo": reflect.TypeOf((*ffi.SortedPrivateSectorInfo)(nil)).Elem(),
	// spec-actor "*Params"
	"SendParams":                           reflect.TypeOf((*puppet.SendParams)(nil)).Elem(),
	"MarketWithdrawBalanceParams":          reflect.TypeOf((*market.WithdrawBalanceParams)(nil)).Elem(),
	"PublishStorageDealsParams":            reflect.TypeOf((*market.PublishStorageDealsParams)(nil)).Elem(),
	"VerifyDealsOnSectorProveCommitParams": reflect.TypeOf((*market.VerifyDealsOnSectorProveCommitParams)(nil)).Elem(),
	"ComputeDataCommitmentParams":          reflect.TypeOf((*market.ComputeDataCommitmentParams)(nil)).Elem(),
	"OnMinerSectorsTerminateParams":        reflect.TypeOf((*market.OnMinerSectorsTerminateParams)(nil)).Elem(),
	"CreateMinerParams":                    reflect.TypeOf((*power.CreateMinerParams)(nil)).Elem(),
	"DeleteMinerParams":                    reflect.TypeOf((*power.DeleteMinerParams)(nil)).Elem(),
	"EnrollCronEventParams":                reflect.TypeOf((*power.EnrollCronEventParams)(nil)).Elem(),
	"OnSectorTerminateParams":              reflect.TypeOf((*power.OnSectorTerminateParams)(nil)).Elem(),
	"OnSectorModifyWeightDescParams":       reflect.TypeOf((*power.OnSectorModifyWeightDescParams)(nil)).Elem(),
	"OnSectorProveCommitParams":            reflect.TypeOf((*power.OnSectorProveCommitParams)(nil)).Elem(),
	"OnFaultBeginParams":                   reflect.TypeOf((*power.OnFaultBeginParams)(nil)).Elem(),
	"OnFaultEndParams":                     reflect.TypeOf((*power.OnFaultEndParams)(nil)).Elem(),
	"MinerConstructorParams":               reflect.TypeOf((*power.MinerConstructorParams)(nil)).Elem(),
	"SubmitWindowedPoStParams":             reflect.TypeOf((*miner.SubmitWindowedPoStParams)(nil)).Elem(),
	"TerminateSectorsParams":               reflect.TypeOf((*miner.TerminateSectorsParams)(nil)).Elem(),
	"ChangePeerIDParams":                   reflect.TypeOf((*miner.ChangePeerIDParams)(nil)).Elem(),
	"ProveCommitSectorParams":              reflect.TypeOf((*miner.ProveCommitSectorParams)(nil)).Elem(),
	"ChangeWorkerAddressParams":            reflect.TypeOf((*miner.ChangeWorkerAddressParams)(nil)).Elem(),
	"ExtendSectorExpirationParams":         reflect.TypeOf((*miner.ExtendSectorExpirationParams)(nil)).Elem(),
	"DeclareFaultsParams":                  reflect.TypeOf((*miner.DeclareFaultsParams)(nil)).Elem(),
	"DeclareFaultsRecoveredParams":         reflect.TypeOf((*miner.DeclareFaultsRecoveredParams)(nil)).Elem(),
	"ReportConsensusFaultParams":           reflect.TypeOf((*miner.ReportConsensusFaultParams)(nil)).Elem(),
	"CheckSectorProvenParams":              reflect.TypeOf((*miner.CheckSectorProvenParams)(nil)).Elem(),
	"MinerWithdrawBalanceParams":           reflect.TypeOf((*miner.WithdrawBalanceParams)(nil)).Elem(),
	"InitConstructorParams":                reflect.TypeOf((*init_.ConstructorParams)(nil)).Elem(),
	"ExecParams":                           reflect.TypeOf((*init_.ExecParams)(nil)).Elem(),
	"AddVerifierParams":                    reflect.TypeOf((*verifreg.AddVerifierParams)(nil)).Elem(),
	"AddVerifiedClientParams":              reflect.TypeOf((*verifreg.AddVerifiedClientParams)(nil)).Elem(),
	"UseBytesParams":                       reflect.TypeOf((*verifreg.UseBytesParams)(nil)).Elem(),
	"RestoreBytesParams":                   reflect.TypeOf((*verifreg.RestoreBytesParams)(nil)).Elem(),
	"CronConstructorParams":                reflect.TypeOf((*cron.ConstructorParams)(nil)).Elem(),
	"MultiSigConstructorParams":            reflect.TypeOf((*multisig.ConstructorParams)(nil)).Elem(),
	"ProposeParams":                        reflect.TypeOf((*multisig.ProposeParams)(nil)).Elem(),
	"AddSignerParams":                      reflect.TypeOf((*multisig.AddSignerParams)(nil)).Elem(),
	"RemoveSignerParams":                   reflect.TypeOf((*multisig.RemoveSignerParams)(nil)).Elem(),
	"TxnIDParams":                          reflect.TypeOf((*multisig.TxnIDParams)(nil)).Elem(),
	"ChangeNumApprovalsThresholdParams":    reflect.TypeOf((*multisig.ChangeNumApprovalsThresholdParams)(nil)).Elem(),
	"SwapSignerParams":                     reflect.TypeOf((*multisig.SwapSignerParams)(nil)).Elem(),
	"PaychConstructorParams":               reflect.TypeOf((*paych.ConstructorParams)(nil)).Elem(),
	"UpdateChannelStateParams":             reflect.TypeOf((*paych.UpdateChannelStateParams)(nil)).Elem(),
	"ModVerifyParams":                      reflect.TypeOf((*paych.ModVerifyParams)(nil)).Elem(),
	"PaymentVerifyParams":                  reflect.TypeOf((*paych.PaymentVerifyParams)(nil)).Elem(),
	"AwardBlockRewardParams":               reflect.TypeOf((*reward.AwardBlockRewardParams)(nil)).Elem(),
}

// PtrToType(typ) should implement CBORer
func cborFuzzUtilRaw(data []byte, typ reflect.Type) int {
	val := reflect.New(typ)
	valIface := val.Interface().(CBORer)
	// Checks for panics unmarshalling arbitrary data
	err := valIface.UnmarshalCBOR(bytes.NewReader(data))
	if err != nil {
		// We expect the vast majority of mutations to fail to unmarshal successfully
		return 0
	}
	buf := new(bytes.Buffer)
	if err := valIface.MarshalCBOR(buf); err != nil {
		panic(fmt.Sprintf("Should be able to successfully marshal something we unmarshalled.\nErr: %v", err))
	}
	// TODO check what an empty slice should decode into?
	data1 := buf.Bytes()
	/*
		if !bytes.Equal(data, data1) {
			// NOTE should be a valid assumption that cbor is deterministic e.g. with field order
			// depends whether this impl is "Canonical CBOR"
			// e.g. https://tools.ietf.org/html/rfc7049#section-3.9
			// https://filecoin-project.github.io/specs/#the-data-model assuming this is "DAG-CBOR", this should be deterministic
			panic("marshal/unmarshal doesn't result in original input - should be canonical")
		}*/

	val1 := reflect.New(typ)
	val1Iface := val1.Interface().(CBORer)
	err = val1Iface.UnmarshalCBOR(bytes.NewReader(data1))
	if err != nil {
		panic(fmt.Sprintf("should be able to unmarshal something we made. Err: %v", err))
	}
	if !dfuzzutil.DeepEqual(valIface, val1Iface) {
		fmt.Printf("result0: %v\n", valIface)
		fmt.Printf("result1: %v\n", val1Iface)
		panic("not equal")
	}
	return 1
}

// PtrToType(typ) should implement CBORer
func cborFuzzUtilStructured(data []byte, typ reflect.Type) int {
	// TODO might want larger maxElements?
	// Is it ok to require non-nil and more than 0 elements?
	// more than 0 elements?
	// nilchance ok or we get rid of it?
	f := gfuzz.NewFromGoFuzz(data).NilChance(0)
	val := reflect.New(typ)
	valIface := val.Interface().(CBORer)
	f.Fuzz(valIface)

	buf := new(bytes.Buffer)
	if err := valIface.MarshalCBOR(buf); err != nil {
		// Main expected errors are writing a CID.undef
		// Most write errors shouldn't occur writing to a bytes.Buffer
		return 0
	}
	rawVal := buf.Bytes()

	val1 := reflect.New(typ)
	val1Iface := val1.Interface().(CBORer)
	err := val1Iface.UnmarshalCBOR(bytes.NewReader(rawVal))
	if err != nil {
		// the marshalled bytes is really the untrusted input, not the struct?
		// but need to be careful about deserializing from blockstore
		fmt.Printf("Generated struct: %#v\n", valIface)
		fmt.Printf("Initial serialized value: %q\n", rawVal)
		// TODO dump cbor bytes here?
		// NOTE: this might not be true, because we won't make something really dodgy?
		// If we marshal it, we should be able to unmarshal though??
		panic(fmt.Sprintf("should be able to unmarshal something we made.\nErr: %v", err))
	}
	if !dfuzzutil.DeepEqual(valIface, val1Iface) {
		// Check that we get back the original data
		fmt.Printf("req0: %#v\n", valIface)
		fmt.Printf("req1: %#v\n", val1Iface)
		panic("not equal")
	}

	buf1 := new(bytes.Buffer)
	if err := val1Iface.MarshalCBOR(buf1); err != nil {
		panic(fmt.Sprintf("should succeed if had done so previously.\nErr: %v", err))
	}
	rawVal1 := buf1.Bytes()
	if !bytes.Equal(rawVal, rawVal1) {
		// TODO print difference here if triggered
		panic("unmarshal-marshal-unmarshal doesn't result in original input - should be canonical")
	}

	return 1
}

// Fuzzing BlockSyncRequest unmarshal/marshal from raw byteslice
func FuzzBlockSyncRequestRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["BlockSyncRequest"])
}

// Fuzzing BlockSyncRequest marshal/unmarshal from generated struct
func FuzzBlockSyncRequestStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["BlockSyncRequest"])
}

// Fuzzing BlockSyncResponse unmarshal/marshal from raw byteslice
func FuzzBlockSyncResponseRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["BlockSyncResponse"])
}

// Fuzzing BlockSyncResponse marshal/unmarshal from generated struct
func FuzzBlockSyncResponseStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["BlockSyncResponse"])
}

// Fuzzing HelloMessage unmarshal/marshal from raw byteslice
func FuzzHelloMessageRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["HelloMessage"])
}

// Fuzzing HelloMessage marshal/unmarshal from generated struct
func FuzzHelloMessageStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["HelloMessage"])
}

// Fuzzing LatencyMessage unmarshal/marshal from raw byteslice
func FuzzLatencyMessageRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["LatencyMessage"])
}

// Fuzzing LatencyMessage marshal/unmarshal from generated struct
func FuzzLatencyMessageStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["LatencyMessage"])
}

// Fuzzing VoucherInfo unmarshal/marshal from raw byteslice
func FuzzVoucherInfoRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["VoucherInfo"])
}

// Fuzzing VoucherInfo marshal/unmarshal from generated struct
func FuzzVoucherInfoStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["VoucherInfo"])
}

// Fuzzing ChannelInfo unmarshal/marshal from raw byteslice
func FuzzChannelInfoRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ChannelInfo"])
}

// Fuzzing ChannelInfo marshal/unmarshal from generated struct
func FuzzChannelInfoStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ChannelInfo"])
}

// Fuzzing PaymentInfo unmarshal/marshal from raw byteslice
func FuzzPaymentInfoRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["PaymentInfo"])
}

// Fuzzing PaymentInfo marshal/unmarshal from generated struct
func FuzzPaymentInfoStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["PaymentInfo"])
}

// Fuzzing SealedRef unmarshal/marshal from raw byteslice
func FuzzSealedRefRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SealedRef"])
}

// Fuzzing SealedRef marshal/unmarshal from generated struct
func FuzzSealedRefStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["SealedRef"])
}

// Fuzzing SealedRefs unmarshal/marshal from raw byteslice
func FuzzSealedRefsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SealedRefs"])
}

// Fuzzing SealedRefs marshal/unmarshal from generated struct
func FuzzSealedRefsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["SealedRefs"])
}

// Fuzzing SealTicket unmarshal/marshal from raw byteslice
func FuzzSealTicketRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SealTicket"])
}

// Fuzzing SealTicket marshal/unmarshal from generated struct
func FuzzSealTicketStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["SealTicket"])
}

// Fuzzing SealSeed unmarshal/marshal from raw byteslice
func FuzzSealSeedRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SealSeed"])
}

// Fuzzing SealSeed marshal/unmarshal from generated struct
func FuzzSealSeedStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["SealSeed"])
}

// Fuzzing Actor unmarshal/marshal from raw byteslice
func FuzzActorRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Actor"])
}

// Fuzzing Actor marshal/unmarshal from generated struct
func FuzzActorStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["Actor"])
}

// Fuzzing TipSet unmarshal/marshal from raw byteslice
func FuzzTipSetRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TipSet"])
}

// Fuzzing TipSet marshal/unmarshal from generated struct
func FuzzTipSetStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["TipSet"])
}

// Fuzzing SignedMessage unmarshal/marshal from raw byteslice
func FuzzSignedMessageRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SignedMessage"])
}

// Fuzzing SignedMessage marshal/unmarshal from generated struct
func FuzzSignedMessageStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["SignedMessage"])
}

// Fuzzing MsgMeta unmarshal/marshal from raw byteslice
func FuzzMsgMetaRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MsgMeta"])
}

// Fuzzing MsgMeta marshal/unmarshal from generated struct
func FuzzMsgMetaStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["MsgMeta"])
}

// Fuzzing MessageReceipt unmarshal/marshal from raw byteslice
func FuzzMessageReceiptRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MessageReceipt"])
}

// Fuzzing MessageReceipt marshal/unmarshal from generated struct
func FuzzMessageReceiptStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["MessageReceipt"])
}

// Fuzzing DealProposal unmarshal/marshal from raw byteslice
func FuzzDealProposalRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["DealProposal"])
}

// Fuzzing DealProposal marshal/unmarshal from generated struct
func FuzzDealProposalStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["DealProposal"])
}

// patrick targets

// Fuzzing SectorInfo unmarshal/marshal from raw byteslice
func FuzzSectorInfoRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SectorInfo"])
}

// Fuzzing SectorInfo unmarshal/marshal from generated struct
func FuzzSectorInfoStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["SectorInfo"])
}

// Fuzzing Piece unmarshal/marshal from raw byteslice
func FuzzPieceRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Piece"])
}

// Fuzzing Piece unmarshal/marshal from generated struct
func FuzzPieceStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["Piece"])
}

// Fuzzing Address unmarshal/marshal from raw byteslice
func FuzzAddressRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Address"])
}

// Fuzzing Address unmarshal/marshal from generated struct
func FuzzAddressStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["Address"])
}

// Fuzzing Deferred unmarshal/marshal from raw byteslice
func FuzzDeferredRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Deferred"])
}

// Fuzzing Deferred unmarshal/marshal from generated struct
func FuzzDeferredStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["Deferred"])
}

// Fuzzing KV unmarshal/marshal from raw byteslice
func FuzzKVRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["KV"])
}

// Fuzzing KV unmarshal/marshal from generated struct
func FuzzKVStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["KV"])
}

// Fuzzing Node unmarshal/marshal from raw byteslice
func FuzzNodeRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Node"])
}

// Fuzzing Node unmarshal/marshal from generated struct
func FuzzNodeStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["Node"])
}

// Fuzzing Pointer unmarshal/marshal from raw byteslice
func FuzzPointerRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Pointer"])
}

// Fuzzing Pointer unmarshal/marshal from generated struct
func FuzzPointerStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["Pointer"])
}

// Fuzzing NodeAmt unmarshal/marshal from raw byteslice
func FuzzNodeAmtRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["NodeAmt"])
}

// Fuzzing NodeAmt unmarshal/marshal from generated struct
func FuzzNodeAmtStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["NodeAmt"])
}

// Fuzzing RootAmt unmarshal/marshal from raw byteslice
func FuzzRootAmtRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["RootAmt"])
}

// Fuzzing RootAmt unmarshal/marshal from generated struct
func FuzzRootAmtStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["RootAmt"])
}

// Fuzzing TestEvent unmarshal/marshal from raw byteslice
func FuzzTestEventRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TestEvent"])
}

// Fuzzing TestEvent unmarshal/marshal from generated struct
func FuzzTestEventStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["TestEvent"])
}

// Fuzzing TestState unmarshal/marshal from raw byteslice
func FuzzTestStateRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TestState"])
}

// Fuzzing TestState unmarshal/marshal from generated struct
func FuzzTestStateStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["TestState"])
}

// Fuzzing DealSchedule unmarshal/marshal from raw byteslice
func FuzzDealScheduleRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["DealSchedule"])
}

// Fuzzing DealSchedule unmarshal/marshal from generated struct
func FuzzDealScheduleStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["DealSchedule"])
}

// Fuzzing DealInfo unmarshal/marshal from raw byteslice
func FuzzDealInfoRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["DealInfo"])
}

// Fuzzing DealInfo unmarshal/marshal from generated struct
func FuzzDealInfoStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["DealInfo"])
}

//TODO DataTransferMessage is an interface not a struct type, need to expose
//the hidden `transferMessage` type
//// Fuzzing DataTransferMessage unmarshal/marshal from raw byteslice
//func FuzzDataTransferMessageRaw(data []byte) int {
//	return cborFuzzUtilRaw(data, cborTypeMap["DataTransferMessage"])
//}
//
//// Fuzzing DataTransferMessage unmarshal/marshal from generated struct
//func FuzzDataTransferMessageStructured(data []byte) int {
//	return cborFuzzUtilStructured(data, cborTypeMap["DataTransferMessage"])
//}

// TODO remove? doesn't implement CBORer
//// Fuzzing SortedPublicSectorInfo unmarshal/marshal from generated struct
//func FuzzSortedPublicSectorInfoStructured(data []byte) int {
//	return cborFuzzUtilStructured(data, cborTypeMap["SortedPublicSectorInfo"])
//}
//
//// Fuzzing SortedPrivateSectorInfo unmarshal/marshal from generated struct
//func FuzzSortedPrivateSectorInfoStructured(data []byte) int {
//	return cborFuzzUtilStructured(data, cborTypeMap["SortedPrivateSectorInfo"])
//}

// spec-actor *Params

// Fuzzing SendParams unmarshal/marshal from raw byteslice
func FuzzSendParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SendParams"])
}

// Fuzzing SendParams marshal/unmarshal from generated struct
func FuzzSendParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["SendParams"])
}

// Fuzzing MarketWithdrawBalanceParams unmarshal/marshal from raw byteslice
func FuzzMarketWithdrawBalanceParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MarketWithdrawBalanceParams"])
}

// Fuzzing MarketWithdrawBalanceParams marshal/unmarshal from generated struct
func FuzzMarketWithdrawBalanceParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["MarketWithdrawBalanceParams"])
}

// Fuzzing PublishStorageDealsParams unmarshal/marshal from raw byteslice
func FuzzPublishStorageDealsParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["PublishStorageDealsParams"])
}

// Fuzzing PublishStorageDealsParams marshal/unmarshal from generated struct
func FuzzPublishStorageDealsParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["PublishStorageDealsParams"])
}

// Fuzzing VerifyDealsOnSectorProveCommitParams unmarshal/marshal from raw byteslice
func FuzzVerifyDealsOnSectorProveCommitParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["VerifyDealsOnSectorProveCommitParams"])
}

// Fuzzing VerifyDealsOnSectorProveCommitParams marshal/unmarshal from generated struct
func FuzzVerifyDealsOnSectorProveCommitParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["VerifyDealsOnSectorProveCommitParams"])
}

// Fuzzing ComputeDataCommitmentParams unmarshal/marshal from raw byteslice
func FuzzComputeDataCommitmentParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ComputeDataCommitmentParams"])
}

// Fuzzing ComputeDataCommitmentParams marshal/unmarshal from generated struct
func FuzzComputeDataCommitmentParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ComputeDataCommitmentParams"])
}

// Fuzzing OnMinerSectorsTerminateParams unmarshal/marshal from raw byteslice
func FuzzOnMinerSectorsTerminateParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["OnMinerSectorsTerminateParams"])
}

// Fuzzing OnMinerSectorsTerminateParams marshal/unmarshal from generated struct
func FuzzOnMinerSectorsTerminateParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["OnMinerSectorsTerminateParams"])
}

// Fuzzing CreateMinerParams unmarshal/marshal from raw byteslice
func FuzzCreateMinerParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["CreateMinerParams"])
}

// Fuzzing CreateMinerParams marshal/unmarshal from generated struct
func FuzzCreateMinerParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["CreateMinerParams"])
}

// Fuzzing DeleteMinerParams unmarshal/marshal from raw byteslice
func FuzzDeleteMinerParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["DeleteMinerParams"])
}

// Fuzzing DeleteMinerParams marshal/unmarshal from generated struct
func FuzzDeleteMinerParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["DeleteMinerParams"])
}

// Fuzzing EnrollCronEventParams unmarshal/marshal from raw byteslice
func FuzzEnrollCronEventParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["EnrollCronEventParams"])
}

// Fuzzing EnrollCronEventParams marshal/unmarshal from generated struct
func FuzzEnrollCronEventParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["EnrollCronEventParams"])
}

// Fuzzing OnSectorTerminateParams unmarshal/marshal from raw byteslice
func FuzzOnSectorTerminateParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["OnSectorTerminateParams"])
}

// Fuzzing OnSectorTerminateParams marshal/unmarshal from generated struct
func FuzzOnSectorTerminateParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["OnSectorTerminateParams"])
}

// Fuzzing OnSectorModifyWeightDescParams unmarshal/marshal from raw byteslice
func FuzzOnSectorModifyWeightDescParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["OnSectorModifyWeightDescParams"])
}

// Fuzzing OnSectorModifyWeightDescParams marshal/unmarshal from generated struct
func FuzzOnSectorModifyWeightDescParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["OnSectorModifyWeightDescParams"])
}

// Fuzzing OnSectorProveCommitParams unmarshal/marshal from raw byteslice
func FuzzOnSectorProveCommitParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["OnSectorProveCommitParams"])
}

// Fuzzing OnSectorProveCommitParams marshal/unmarshal from generated struct
func FuzzOnSectorProveCommitParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["OnSectorProveCommitParams"])
}

// Fuzzing OnFaultBeginParams unmarshal/marshal from raw byteslice
func FuzzOnFaultBeginParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["OnFaultBeginParams"])
}

// Fuzzing OnFaultBeginParams marshal/unmarshal from generated struct
func FuzzOnFaultBeginParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["OnFaultBeginParams"])
}

// Fuzzing OnFaultEndParams unmarshal/marshal from raw byteslice
func FuzzOnFaultEndParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["OnFaultEndParams"])
}

// Fuzzing OnFaultEndParams marshal/unmarshal from generated struct
func FuzzOnFaultEndParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["OnFaultEndParams"])
}

// Fuzzing MinerConstructorParams unmarshal/marshal from raw byteslice
func FuzzMinerConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MinerConstructorParams"])
}

// Fuzzing MinerConstructorParams marshal/unmarshal from generated struct
func FuzzMinerConstructorParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["MinerConstructorParams"])
}

// Fuzzing SubmitWindowedPoStParams unmarshal/marshal from raw byteslice
func FuzzSubmitWindowedPoStParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SubmitWindowedPoStParams"])
}

// Fuzzing SubmitWindowedPoStParams marshal/unmarshal from generated struct
func FuzzSubmitWindowedPoStParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["SubmitWindowedPoStParams"])
}

// Fuzzing TerminateSectorsParams unmarshal/marshal from raw byteslice
func FuzzTerminateSectorsParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TerminateSectorsParams"])
}

// Fuzzing TerminateSectorsParams marshal/unmarshal from generated struct
func FuzzTerminateSectorsParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["TerminateSectorsParams"])
}

// Fuzzing ChangePeerIDParams unmarshal/marshal from raw byteslice
func FuzzChangePeerIDParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ChangePeerIDParams"])
}

// Fuzzing ChangePeerIDParams marshal/unmarshal from generated struct
func FuzzChangePeerIDParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ChangePeerIDParams"])
}

// Fuzzing ProveCommitSectorParams unmarshal/marshal from raw byteslice
func FuzzProveCommitSectorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ProveCommitSectorParams"])
}

// Fuzzing ProveCommitSectorParams marshal/unmarshal from generated struct
func FuzzProveCommitSectorParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ProveCommitSectorParams"])
}

// Fuzzing ChangeWorkerAddressParams unmarshal/marshal from raw byteslice
func FuzzChangeWorkerAddressParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ChangeWorkerAddressParams"])
}

// Fuzzing ChangeWorkerAddressParams marshal/unmarshal from generated struct
func FuzzChangeWorkerAddressParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ChangeWorkerAddressParams"])
}

// Fuzzing ExtendSectorExpirationParams unmarshal/marshal from raw byteslice
func FuzzExtendSectorExpirationParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ExtendSectorExpirationParams"])
}

// Fuzzing ExtendSectorExpirationParams marshal/unmarshal from generated struct
func FuzzExtendSectorExpirationParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ExtendSectorExpirationParams"])
}

// Fuzzing DeclareFaultsParams unmarshal/marshal from raw byteslice
func FuzzDeclareFaultsParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["DeclareFaultsParams"])
}

// Fuzzing DeclareFaultsParams marshal/unmarshal from generated struct
func FuzzDeclareFaultsParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["DeclareFaultsParams"])
}

// Fuzzing DeclareFaultsRecoveredParams unmarshal/marshal from raw byteslice
func FuzzDeclareFaultsRecoveredParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["DeclareFaultsRecoveredParams"])
}

// Fuzzing DeclareFaultsRecoveredParams marshal/unmarshal from generated struct
func FuzzDeclareFaultsRecoveredParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["DeclareFaultsRecoveredParams"])
}

// Fuzzing ReportConsensusFaultParams unmarshal/marshal from raw byteslice
func FuzzReportConsensusFaultParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ReportConsensusFaultParams"])
}

// Fuzzing ReportConsensusFaultParams marshal/unmarshal from generated struct
func FuzzReportConsensusFaultParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ReportConsensusFaultParams"])
}

// Fuzzing CheckSectorProvenParams unmarshal/marshal from raw byteslice
func FuzzCheckSectorProvenParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["CheckSectorProvenParams"])
}

// Fuzzing CheckSectorProvenParams marshal/unmarshal from generated struct
func FuzzCheckSectorProvenParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["CheckSectorProvenParams"])
}

// Fuzzing MinerWithdrawBalanceParams unmarshal/marshal from raw byteslice
func FuzzMinerWithdrawBalanceParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MinerWithdrawBalanceParams"])
}

// Fuzzing MinerWithdrawBalanceParams marshal/unmarshal from generated struct
func FuzzMinerWithdrawBalanceParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["MinerWithdrawBalanceParams"])
}

// Fuzzing InitConstructorParams unmarshal/marshal from raw byteslice
func FuzzInitConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["InitConstructorParams"])
}

// Fuzzing InitConstructorParams marshal/unmarshal from generated struct
func FuzzInitConstructorParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["InitConstructorParams"])
}

// Fuzzing ExecParams unmarshal/marshal from raw byteslice
func FuzzExecParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ExecParams"])
}

// Fuzzing ExecParams marshal/unmarshal from generated struct
func FuzzExecParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ExecParams"])
}

// Fuzzing AddVerifierParams unmarshal/marshal from raw byteslice
func FuzzAddVerifierParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["AddVerifierParams"])
}

// Fuzzing AddVerifierParams marshal/unmarshal from generated struct
func FuzzAddVerifierParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["AddVerifierParams"])
}

// Fuzzing AddVerifiedClientParams unmarshal/marshal from raw byteslice
func FuzzAddVerifiedClientParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["AddVerifiedClientParams"])
}

// Fuzzing AddVerifiedClientParams marshal/unmarshal from generated struct
func FuzzAddVerifiedClientParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["AddVerifiedClientParams"])
}

// Fuzzing UseBytesParams unmarshal/marshal from raw byteslice
func FuzzUseBytesParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["UseBytesParams"])
}

// Fuzzing UseBytesParams marshal/unmarshal from generated struct
func FuzzUseBytesParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["UseBytesParams"])
}

// Fuzzing RestoreBytesParams unmarshal/marshal from raw byteslice
func FuzzRestoreBytesParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["RestoreBytesParams"])
}

// Fuzzing RestoreBytesParams marshal/unmarshal from generated struct
func FuzzRestoreBytesParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["RestoreBytesParams"])
}

// Fuzzing CronConstructorParams unmarshal/marshal from raw byteslice
func FuzzCronConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["CronConstructorParams"])
}

// Fuzzing CronConstructorParams marshal/unmarshal from generated struct
func FuzzCronConstructorParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["CronConstructorParams"])
}

// Fuzzing MultiSigConstructorParams unmarshal/marshal from raw byteslice
func FuzzMultiSigConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MultiSigConstructorParams"])
}

// Fuzzing MultiSigConstructorParams marshal/unmarshal from generated struct
func FuzzMultiSigConstructorParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["MultiSigConstructorParams"])
}

// Fuzzing ProposeParams unmarshal/marshal from raw byteslice
func FuzzProposeParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ProposeParams"])
}

// Fuzzing ProposeParams marshal/unmarshal from generated struct
func FuzzProposeParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ProposeParams"])
}

// Fuzzing AddSignerParams unmarshal/marshal from raw byteslice
func FuzzAddSignerParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["AddSignerParams"])
}

// Fuzzing AddSignerParams marshal/unmarshal from generated struct
func FuzzAddSignerParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["AddSignerParams"])
}

// Fuzzing RemoveSignerParams unmarshal/marshal from raw byteslice
func FuzzRemoveSignerParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["RemoveSignerParams"])
}

// Fuzzing RemoveSignerParams marshal/unmarshal from generated struct
func FuzzRemoveSignerParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["RemoveSignerParams"])
}

// Fuzzing TxnIDParams unmarshal/marshal from raw byteslice
func FuzzTxnIDParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TxnIDParams"])
}

// Fuzzing TxnIDParams marshal/unmarshal from generated struct
func FuzzTxnIDParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["TxnIDParams"])
}

// Fuzzing ChangeNumApprovalsThresholdParams unmarshal/marshal from raw byteslice
func FuzzChangeNumApprovalsThresholdParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ChangeNumApprovalsThresholdParams"])
}

// Fuzzing ChangeNumApprovalsThresholdParams marshal/unmarshal from generated struct
func FuzzChangeNumApprovalsThresholdParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ChangeNumApprovalsThresholdParams"])
}

// Fuzzing SwapSignerParams unmarshal/marshal from raw byteslice
func FuzzSwapSignerParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SwapSignerParams"])
}

// Fuzzing SwapSignerParams marshal/unmarshal from generated struct
func FuzzSwapSignerParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["SwapSignerParams"])
}

// Fuzzing PaychConstructorParams unmarshal/marshal from raw byteslice
func FuzzPaychConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["PaychConstructorParams"])
}

// Fuzzing PaychConstructorParams marshal/unmarshal from generated struct
func FuzzPaychConstructorParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["PaychConstructorParams"])
}

// Fuzzing UpdateChannelStateParams unmarshal/marshal from raw byteslice
func FuzzUpdateChannelStateParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["UpdateChannelStateParams"])
}

// Fuzzing UpdateChannelStateParams marshal/unmarshal from generated struct
func FuzzUpdateChannelStateParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["UpdateChannelStateParams"])
}

// Fuzzing ModVerifyParams unmarshal/marshal from raw byteslice
func FuzzModVerifyParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ModVerifyParams"])
}

// Fuzzing ModVerifyParams marshal/unmarshal from generated struct
func FuzzModVerifyParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["ModVerifyParams"])
}

// Fuzzing PaymentVerifyParams unmarshal/marshal from raw byteslice
func FuzzPaymentVerifyParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["PaymentVerifyParams"])
}

// Fuzzing PaymentVerifyParams marshal/unmarshal from generated struct
func FuzzPaymentVerifyParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["PaymentVerifyParams"])
}

// Fuzzing AwardBlockRewardParams unmarshal/marshal from raw byteslice
func FuzzAwardBlockRewardParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["AwardBlockRewardParams"])
}

// Fuzzing AwardBlockRewardParams marshal/unmarshal from generated struct
func FuzzAwardBlockRewardParamsStructured(data []byte) int {
	return cborFuzzUtilStructured(data, cborTypeMap["AwardBlockRewardParams"])
}
