// Contains fuzzing harnesses to be run through OSS-fuzz

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
	"MarketWithdrawBalanceParams":          reflect.TypeOf((*market.WithdrawBalanceParams)(nil)).Elem(),
	"PublishStorageDealsParams":            reflect.TypeOf((*market.PublishStorageDealsParams)(nil)).Elem(),
	"ComputeDataCommitmentParams":          reflect.TypeOf((*market.ComputeDataCommitmentParams)(nil)).Elem(),
	"OnMinerSectorsTerminateParams":        reflect.TypeOf((*market.OnMinerSectorsTerminateParams)(nil)).Elem(),
	"CreateMinerParams":                    reflect.TypeOf((*power.CreateMinerParams)(nil)).Elem(),
	"EnrollCronEventParams":                reflect.TypeOf((*power.EnrollCronEventParams)(nil)).Elem(),
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
		return 0
	}
	// TODO check what an empty slice should decode into?
	data1 := buf.Bytes()

	val1 := reflect.New(typ)
	val1Iface := val1.Interface().(CBORer)
	err = val1Iface.UnmarshalCBOR(bytes.NewReader(data1))
	if err != nil {
		return 0
	}
	if !dfuzzutil.DeepEqual(valIface, val1Iface) {
		fmt.Printf("result0: %v\n", valIface)
		fmt.Printf("result1: %v\n", val1Iface)
		return 0
	}
	return 1
}


// Fuzzing HelloMessage unmarshal/marshal from raw byteslice
func FuzzHelloMessageRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["HelloMessage"])
}

// Fuzzing LatencyMessage unmarshal/marshal from raw byteslice
func FuzzLatencyMessageRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["LatencyMessage"])
}

// Fuzzing VoucherInfo unmarshal/marshal from raw byteslice
func FuzzVoucherInfoRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["VoucherInfo"])
}

// Fuzzing ChannelInfo unmarshal/marshal from raw byteslice
func FuzzChannelInfoRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ChannelInfo"])
}

// Fuzzing PaymentInfo unmarshal/marshal from raw byteslice
func FuzzPaymentInfoRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["PaymentInfo"])
}

// Fuzzing SealedRef unmarshal/marshal from raw byteslice
func FuzzSealedRefRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SealedRef"])
}

// Fuzzing SealedRefs unmarshal/marshal from raw byteslice
func FuzzSealedRefsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SealedRefs"])
}

// Fuzzing SealTicket unmarshal/marshal from raw byteslice
func FuzzSealTicketRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SealTicket"])
}

// Fuzzing SealSeed unmarshal/marshal from raw byteslice
func FuzzSealSeedRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SealSeed"])
}

// Fuzzing Actor unmarshal/marshal from raw byteslice
func FuzzActorRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Actor"])
}

// Fuzzing TipSet unmarshal/marshal from raw byteslice
func FuzzTipSetRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TipSet"])
}

// Fuzzing SignedMessage unmarshal/marshal from raw byteslice
func FuzzSignedMessageRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SignedMessage"])
}

// Fuzzing MsgMeta unmarshal/marshal from raw byteslice
func FuzzMsgMetaRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MsgMeta"])
}

// Fuzzing MessageReceipt unmarshal/marshal from raw byteslice
func FuzzMessageReceiptRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MessageReceipt"])
}

// Fuzzing DealProposal unmarshal/marshal from raw byteslice
func FuzzDealProposalRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["DealProposal"])
}

// patrick targets

// Fuzzing Address unmarshal/marshal from raw byteslice
func FuzzAddressRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Address"])
}

// Fuzzing Deferred unmarshal/marshal from raw byteslice
func FuzzDeferredRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Deferred"])
}

// Fuzzing KV unmarshal/marshal from raw byteslice
func FuzzKVRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["KV"])
}

// Fuzzing Node unmarshal/marshal from raw byteslice
func FuzzNodeRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Node"])
}

// Fuzzing Pointer unmarshal/marshal from raw byteslice
func FuzzPointerRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["Pointer"])
}

// Fuzzing NodeAmt unmarshal/marshal from raw byteslice
func FuzzNodeAmtRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["NodeAmt"])
}

// Fuzzing RootAmt unmarshal/marshal from raw byteslice
func FuzzRootAmtRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["RootAmt"])
}

// Fuzzing TestEvent unmarshal/marshal from raw byteslice
func FuzzTestEventRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TestEvent"])
}

// Fuzzing TestState unmarshal/marshal from raw byteslice
func FuzzTestStateRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TestState"])
}


// spec-actor *Params

// Fuzzing MarketWithdrawBalanceParams unmarshal/marshal from raw byteslice
func FuzzMarketWithdrawBalanceParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MarketWithdrawBalanceParams"])
}

// Fuzzing PublishStorageDealsParams unmarshal/marshal from raw byteslice
func FuzzPublishStorageDealsParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["PublishStorageDealsParams"])
}


// Fuzzing ComputeDataCommitmentParams unmarshal/marshal from raw byteslice
func FuzzComputeDataCommitmentParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ComputeDataCommitmentParams"])
}

// Fuzzing OnMinerSectorsTerminateParams unmarshal/marshal from raw byteslice
func FuzzOnMinerSectorsTerminateParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["OnMinerSectorsTerminateParams"])
}

// Fuzzing CreateMinerParams unmarshal/marshal from raw byteslice
func FuzzCreateMinerParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["CreateMinerParams"])
}

// Fuzzing EnrollCronEventParams unmarshal/marshal from raw byteslice
func FuzzEnrollCronEventParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["EnrollCronEventParams"])
}

// Fuzzing MinerConstructorParams unmarshal/marshal from raw byteslice
func FuzzMinerConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MinerConstructorParams"])
}

// Fuzzing SubmitWindowedPoStParams unmarshal/marshal from raw byteslice
func FuzzSubmitWindowedPoStParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SubmitWindowedPoStParams"])
}

// Fuzzing TerminateSectorsParams unmarshal/marshal from raw byteslice
func FuzzTerminateSectorsParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TerminateSectorsParams"])
}

// Fuzzing ChangePeerIDParams unmarshal/marshal from raw byteslice
func FuzzChangePeerIDParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ChangePeerIDParams"])
}

// Fuzzing ProveCommitSectorParams unmarshal/marshal from raw byteslice
func FuzzProveCommitSectorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ProveCommitSectorParams"])
}

// Fuzzing ChangeWorkerAddressParams unmarshal/marshal from raw byteslice
func FuzzChangeWorkerAddressParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ChangeWorkerAddressParams"])
}

// Fuzzing ExtendSectorExpirationParams unmarshal/marshal from raw byteslice
func FuzzExtendSectorExpirationParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ExtendSectorExpirationParams"])
}

// Fuzzing DeclareFaultsParams unmarshal/marshal from raw byteslice
func FuzzDeclareFaultsParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["DeclareFaultsParams"])
}

// Fuzzing DeclareFaultsRecoveredParams unmarshal/marshal from raw byteslice
func FuzzDeclareFaultsRecoveredParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["DeclareFaultsRecoveredParams"])
}

// Fuzzing ReportConsensusFaultParams unmarshal/marshal from raw byteslice
func FuzzReportConsensusFaultParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ReportConsensusFaultParams"])
}

// Fuzzing CheckSectorProvenParams unmarshal/marshal from raw byteslice
func FuzzCheckSectorProvenParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["CheckSectorProvenParams"])
}

// Fuzzing MinerWithdrawBalanceParams unmarshal/marshal from raw byteslice
func FuzzMinerWithdrawBalanceParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MinerWithdrawBalanceParams"])
}

// Fuzzing InitConstructorParams unmarshal/marshal from raw byteslice
func FuzzInitConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["InitConstructorParams"])
}

// Fuzzing ExecParams unmarshal/marshal from raw byteslice
func FuzzExecParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ExecParams"])
}

// Fuzzing AddVerifierParams unmarshal/marshal from raw byteslice
func FuzzAddVerifierParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["AddVerifierParams"])
}

// Fuzzing AddVerifiedClientParams unmarshal/marshal from raw byteslice
func FuzzAddVerifiedClientParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["AddVerifiedClientParams"])
}

// Fuzzing UseBytesParams unmarshal/marshal from raw byteslice
func FuzzUseBytesParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["UseBytesParams"])
}

// Fuzzing RestoreBytesParams unmarshal/marshal from raw byteslice
func FuzzRestoreBytesParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["RestoreBytesParams"])
}

// Fuzzing CronConstructorParams unmarshal/marshal from raw byteslice
func FuzzCronConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["CronConstructorParams"])
}

// Fuzzing MultiSigConstructorParams unmarshal/marshal from raw byteslice
func FuzzMultiSigConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["MultiSigConstructorParams"])
}

// Fuzzing ProposeParams unmarshal/marshal from raw byteslice
func FuzzProposeParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ProposeParams"])
}

// Fuzzing AddSignerParams unmarshal/marshal from raw byteslice
func FuzzAddSignerParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["AddSignerParams"])
}

// Fuzzing RemoveSignerParams unmarshal/marshal from raw byteslice
func FuzzRemoveSignerParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["RemoveSignerParams"])
}

// Fuzzing TxnIDParams unmarshal/marshal from raw byteslice
func FuzzTxnIDParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["TxnIDParams"])
}

// Fuzzing ChangeNumApprovalsThresholdParams unmarshal/marshal from raw byteslice
func FuzzChangeNumApprovalsThresholdParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ChangeNumApprovalsThresholdParams"])
}

// Fuzzing SwapSignerParams unmarshal/marshal from raw byteslice
func FuzzSwapSignerParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["SwapSignerParams"])
}

// Fuzzing PaychConstructorParams unmarshal/marshal from raw byteslice
func FuzzPaychConstructorParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["PaychConstructorParams"])
}

// Fuzzing UpdateChannelStateParams unmarshal/marshal from raw byteslice
func FuzzUpdateChannelStateParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["UpdateChannelStateParams"])
}

// Fuzzing ModVerifyParams unmarshal/marshal from raw byteslice
func FuzzModVerifyParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["ModVerifyParams"])
}

// Fuzzing PaymentVerifyParams unmarshal/marshal from raw byteslice
func FuzzPaymentVerifyParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["PaymentVerifyParams"])
}

// Fuzzing AwardBlockRewardParams unmarshal/marshal from raw byteslice
func FuzzAwardBlockRewardParamsRaw(data []byte) int {
	return cborFuzzUtilRaw(data, cborTypeMap["AwardBlockRewardParams"])
}
