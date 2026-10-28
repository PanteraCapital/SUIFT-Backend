package vm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	builderCapella "github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/suave/artifacts"
	suave "github.com/ethereum/go-ethereum/suave/core"
	"github.com/ethereum/go-ethereum/suave/cstore"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/stretchr/testify/require"
)

// SUAVE_BUILDER_CONTRACT is the operator-configured builder contract, as a
// hex address. buildEthBlock must read it on every call. An empty or unset
// value authorizes no caller. A call is authorized only when that address
// appears on the confidential caller stack and is not the buildEthBlock
// precompile itself. Transaction origin is not authorization.
//
// The kettle may return one signed builder bid per slot. Reserve the slot
// before BuildEthBlockFromBundles returns so two overlapping calls cannot
// both come back with a signature. A refused call must not return bytes that
// verify under the kettle BLS key, and must not sign a different payload
// than the one just built for the authorized call.
//
// The same rules apply to every entry point that reaches buildEthBlock.runImpl,
// including the confidential EVM precompile and RunConfidential.
const suaveBuilderContractEnv = "SUAVE_BUILDER_CONTRACT"

// goerliBuilderDomain is the signing domain hardcoded in buildEthBlock.
var goerliBuilderDomain = ssz.ComputeDomain(ssz.DomainTypeAppBuilder, phase0.Version{0x00, 0x00, 0x10, 0x20}, phase0.Root{})

var (
	kettleBuilderContract  = common.HexToAddress("0xB111000000000000000000000000000000000001")
	kettleAttackerContract = common.HexToAddress("0xA77AC00000000000000000000000000000000001")
	kettleAttackerOrigin   = common.HexToAddress("0xA77AC0000000000000000000000000000000000e")
)

var kettleSlotSeq uint64 = 8_000_000

func nextKettleSlot() uint64 {
	return atomic.AddUint64(&kettleSlotSeq, 1)
}

// payloadBackend stands in for the execution-layer block builder. The real
// worker copies parent, timestamp, coinbase, gas limit, prevrandao and
// withdrawals from the build args, then always appends a proposer payment
// transaction. This stub returns those same fields and a non-empty
// transaction so the precompile's signing inputs are the ones the builder
// would have produced. It does not sign.
type payloadBackend struct {
	delay time.Duration
}

func (p *payloadBackend) BuildEthBlock(ctx context.Context, args *types.BuildBlockArgs, txs types.Transactions) (*engine.ExecutionPayloadEnvelope, error) {
	return p.BuildEthBlockFromBundles(ctx, args, nil)
}

func (p *payloadBackend) BuildEthBlockFromBundles(ctx context.Context, args *types.BuildBlockArgs, bundles []types.SBundle) (*engine.ExecutionPayloadEnvelope, error) {
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	gasLimit := args.GasLimit
	if gasLimit == 0 {
		gasLimit = 30_000_000
	}
	blockHash := crypto.Keccak256Hash(args.Parent.Bytes(), args.Random.Bytes(), args.FeeRecipient.Bytes())
	payload := &engine.ExecutableData{
		ParentHash:    args.Parent,
		FeeRecipient:  args.FeeRecipient,
		StateRoot:     common.Hash{0x11},
		ReceiptsRoot:  common.Hash{0x22},
		LogsBloom:     make([]byte, 256),
		Random:        args.Random,
		Number:        1,
		GasLimit:      gasLimit,
		GasUsed:       21_000,
		Timestamp:     args.Timestamp,
		ExtraData:     []byte{},
		BaseFeePerGas: big.NewInt(1),
		BlockHash:     blockHash,
		Transactions:  [][]byte{{0x02, 0x01}},
		Withdrawals:   []*types.Withdrawal{},
	}
	return &engine.ExecutionPayloadEnvelope{
		ExecutionPayload: payload,
		BlockValue:       big.NewInt(1_000_000_000_000_000_000),
	}, nil
}

func (p *payloadBackend) Call(ctx context.Context, contractAddr common.Address, input []byte) ([]byte, error) {
	return nil, nil
}

type kettleHarness struct {
	t       *testing.T
	sk      *bls.SecretKey
	pkBytes []byte
	backend *SuaveExecutionBackend
	rt      *suaveRuntime
	bundle  []byte
	payload *payloadBackend
}

func newKettleHarness(t *testing.T) *kettleHarness {
	t.Helper()
	sk, pk, err := bls.GenerateNewKeypair()
	require.NoError(t, err)

	confStore := cstore.NewLocalConfidentialStore()
	confEngine := cstore.NewConfidentialStoreEngine(confStore, &cstore.MockTransport{}, cstore.MockSigner{}, cstore.MockChainSigner{})
	require.NoError(t, confEngine.Start())
	t.Cleanup(func() { confEngine.Stop() })

	reqTx := types.NewTx(&types.ConfidentialComputeRequest{
		ConfidentialComputeRecord: types.ConfidentialComputeRecord{
			ExecutionNode: common.Address{0xee},
		},
	})
	payload := &payloadBackend{}
	backend := &SuaveExecutionBackend{
		EthBlockSigningKey:     sk,
		ConfidentialStore:      confEngine.NewTransactionalStore(reqTx),
		ConfidentialEthBackend: payload,
	}
	bundle, err := json.Marshal(&types.SBundle{BlockNumber: big.NewInt(1), Txs: types.Transactions{}})
	require.NoError(t, err)

	return &kettleHarness{
		t:       t,
		sk:      sk,
		pkBytes: bls.PublicKeyToBytes(pk),
		backend: backend,
		payload: payload,
		bundle:  bundle,
		rt: &suaveRuntime{suaveContext: &SuaveContext{
			Backend:                      backend,
			ConfidentialComputeRequestTx: reqTx,
		}},
	}
}

func (h *kettleHarness) allowBuilder(t *testing.T) {
	t.Helper()
	t.Setenv(suaveBuilderContractEnv, kettleBuilderContract.Hex())
}

func (h *kettleHarness) storeBid(owner common.Address, version, key string, value []byte, peekers []common.Address) types.Bid {
	h.t.Helper()
	caller := owner
	h.rt.suaveContext.CallerStack = []*common.Address{&caller}
	bid, err := h.rt.newBid(1, peekers, nil, version)
	require.NoError(h.t, err)
	if value != nil {
		require.NoError(h.t, h.rt.confidentialStore(bid.Id, key, value))
	}
	return bid
}

func (h *kettleHarness) attackerBid(version, key string) types.Bid {
	return h.storeBid(kettleAttackerContract, version, key, h.bundle, []common.Address{kettleAttackerContract, buildEthBlockAddress})
}

func (h *kettleHarness) builderBid(version, key string) types.Bid {
	return h.storeBid(kettleBuilderContract, version, key, h.bundle, []common.Address{kettleBuilderContract, buildEthBlockAddress})
}

func kettleBlockArgs(slot uint64, parent, random byte, fee byte) types.BuildBlockArgs {
	var proposer [48]byte
	for i := range proposer {
		proposer[i] = byte(i + 1)
	}
	return types.BuildBlockArgs{
		Slot:           slot,
		ProposerPubkey: proposer[:],
		Parent:         common.Hash{parent},
		Timestamp:      1_680_000_000,
		FeeRecipient:   common.Address{fee},
		GasLimit:       30_000_000,
		Random:         common.Hash{random},
		Withdrawals:    []*types.Withdrawal{},
	}
}

func precompileForwarder(addr common.Address) []byte {
	// Forwards calldata with STATICCALL and returns or reverts with the
	// precompile's return data. Stack order matches opStaticCall,
	// opCallDataCopy and opReturnDataCopy in core/vm/instructions.go.
	code := []byte{
		0x36, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATASIZE, PUSH1 0, PUSH1 0, CALLDATACOPY
		0x60, 0x00, // retSize
		0x60, 0x00, // retOffset
		0x36,       // argsSize
		0x60, 0x00, // argsOffset
		0x73,
	}
	code = append(code, addr.Bytes()...)
	code = append(code,
		0x5a,             // GAS
		0xfa,             // STATICCALL
		0x15,             // ISZERO
		0x61, 0x00, 0x33, // PUSH2 revert
		0x57,       // JUMPI
		0x3d,       // RETURNDATASIZE
		0x60, 0x00, // dataOffset
		0x60, 0x00, // memOffset
		0x3e,       // RETURNDATACOPY
		0x3d,       // RETURNDATASIZE
		0x60, 0x00, // offset
		0xf3, // RETURN
		0x5b, // JUMPDEST at 0x33
		0x3d,
		0x60, 0x00,
		0x60, 0x00,
		0x3e,
		0x3d,
		0x60, 0x00,
		0xfd, // REVERT
	)
	return code
}

func (h *kettleHarness) evm(origin common.Address, contracts ...common.Address) *EVM {
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	require.NoError(h.t, err)
	code := precompileForwarder(buildEthBlockAddress)
	for _, addr := range contracts {
		statedb.CreateAccount(addr)
		statedb.SetCode(addr, code)
	}
	blockCtx := dummyBlockContext
	blockCtx.GasLimit = 30_000_000
	blockCtx.BaseFee = big.NewInt(1)
	blockCtx.Time = 1_680_000_000
	return NewConfidentialEVM(SuaveContext{
		Backend:                      h.backend,
		ConfidentialComputeRequestTx: h.rt.suaveContext.ConfidentialComputeRequestTx,
	}, blockCtx, TxContext{Origin: origin, GasPrice: big.NewInt(1)}, statedb, params.AllEthashProtocolChanges, Config{IsConfidential: true})
}

func (h *kettleHarness) pack(args types.BuildBlockArgs, bidID types.BidId) []byte {
	h.t.Helper()
	packed, err := artifacts.SuaveAbi.Methods["buildEthBlock"].Inputs.Pack(args, bidID, "")
	require.NoError(h.t, err)
	return packed
}

func (h *kettleHarness) callContract(contract, origin common.Address, args types.BuildBlockArgs, bidID types.BidId) ([]byte, error) {
	h.t.Helper()
	evm := h.evm(origin, contract)
	ret, _, err := evm.Call(AccountRef(origin), contract, h.pack(args, bidID), 3_000_000, big.NewInt(0))
	return ret, err
}

func (h *kettleHarness) callPrecompile(origin common.Address, args types.BuildBlockArgs, bidID types.BidId) ([]byte, error) {
	h.t.Helper()
	evm := h.evm(origin)
	ret, _, err := evm.Call(AccountRef(origin), buildEthBlockAddress, h.pack(args, bidID), 3_000_000, big.NewInt(0))
	return ret, err
}

func (h *kettleHarness) callerContext(caller common.Address) *SuaveContext {
	callerCopy := caller
	precompile := buildEthBlockAddress
	return &SuaveContext{
		Backend:                      h.backend,
		ConfidentialComputeRequestTx: h.rt.suaveContext.ConfidentialComputeRequestTx,
		CallerStack:                  []*common.Address{&callerCopy, &precompile},
	}
}

// callRunImpl is the shared implementation behind the EVM adapter and
// RunConfidential. The adapter is what a confidential contract actually hits.
func (h *kettleHarness) callRunImpl(caller common.Address, args types.BuildBlockArgs, bidID types.BidId) ([]byte, error) {
	h.t.Helper()
	bidBytes, _, err := (&buildEthBlock{}).runImpl(h.callerContext(caller), args, bidID, "")
	return bidBytes, err
}

func (h *kettleHarness) verifyingBid(ret []byte) (*builderCapella.SubmitBlockRequest, bool) {
	candidates := [][]byte{ret}
	if unpacked, err := artifacts.SuaveAbi.Methods["buildEthBlock"].Outputs.Unpack(ret); err == nil && len(unpacked) > 0 {
		if raw, ok := unpacked[0].([]byte); ok {
			candidates = append(candidates, raw)
		}
	}
	for _, candidate := range candidates {
		var req builderCapella.SubmitBlockRequest
		if err := json.Unmarshal(candidate, &req); err != nil || req.Message == nil {
			continue
		}
		ok, err := ssz.VerifySignature(req.Message, goerliBuilderDomain, h.pkBytes, req.Signature[:])
		if err == nil && ok {
			return &req, true
		}
	}
	return nil, false
}

func (h *kettleHarness) requireRefusal(ret []byte, err error) {
	h.t.Helper()
	if req, ok := h.verifyingBid(ret); ok {
		h.t.Fatalf("caller received a kettle-signed bid for slot %d parent %x block %x proposer %x",
			req.Message.Slot, req.Message.ParentHash, req.Message.BlockHash, req.Message.ProposerPubkey)
	}
	if err == nil {
		h.t.Fatalf("buildEthBlock succeeded for an unauthorized caller or a repeated slot, return %q", ret)
	}
}

func (h *kettleHarness) requireSigned(ret []byte, err error, args types.BuildBlockArgs) *builderCapella.SubmitBlockRequest {
	h.t.Helper()
	require.NoError(h.t, err)
	req, ok := h.verifyingBid(ret)
	if !ok {
		h.t.Fatalf("authorized builder did not receive a verifying kettle signature, return %q", ret)
	}
	if req.Message.Slot != args.Slot {
		h.t.Fatalf("signed slot %d, requested slot %d", req.Message.Slot, args.Slot)
	}
	if !bytes.Equal(req.Message.ParentHash[:], args.Parent[:]) {
		h.t.Fatalf("signed parent %x, requested parent %x", req.Message.ParentHash, args.Parent)
	}
	if !bytes.Equal(req.Message.ProposerPubkey[:], args.ProposerPubkey) {
		h.t.Fatalf("signed proposer %x, requested proposer %x", req.Message.ProposerPubkey, args.ProposerPubkey)
	}
	if !bytes.Equal(req.Message.ProposerFeeRecipient[:], args.FeeRecipient[:]) {
		h.t.Fatalf("signed fee recipient %x, requested %x", req.Message.ProposerFeeRecipient, args.FeeRecipient)
	}
	if !bytes.Equal(req.Message.BuilderPubkey[:], h.pkBytes) {
		h.t.Fatalf("signed builder pubkey %x is not the kettle key %x", req.Message.BuilderPubkey, h.pkBytes)
	}
	if req.Message.Value == nil || req.Message.Value.ToBig().Sign() == 0 {
		h.t.Fatalf("signed bid value is zero")
	}
	if req.ExecutionPayload == nil || len(req.ExecutionPayload.Transactions) == 0 {
		h.t.Fatalf("signed execution payload has no transactions")
	}
	wantHash := crypto.Keccak256Hash(args.Parent.Bytes(), args.Random.Bytes(), args.FeeRecipient.Bytes())
	if !bytes.Equal(req.Message.BlockHash[:], wantHash[:]) {
		h.t.Fatalf("signed block hash %x, payload built for these args hashes to %x", req.Message.BlockHash, wantHash)
	}
	return req
}

func TestKettleBuilderBid_UntrustedContractCannotObtainSignature(t *testing.T) {
	h := newKettleHarness(t)
	h.allowBuilder(t)
	bid := h.attackerBid("default:v0:ethBundles", "default:v0:ethBundles")
	args := kettleBlockArgs(nextKettleSlot(), 0xaa, 0x01, 0x42)

	// Origin is the configured builder. Authorization has to follow the
	// contract on the caller stack, which is the attacker's contract.
	ret, err := h.callContract(kettleAttackerContract, kettleBuilderContract, args, bid.Id)
	h.requireRefusal(ret, err)
}

func TestKettleBuilderBid_BuilderListedAsPeekerIsNotAuthorization(t *testing.T) {
	h := newKettleHarness(t)
	h.allowBuilder(t)
	bid := h.storeBid(kettleAttackerContract, "default:v0:ethBundles", "default:v0:ethBundles", h.bundle,
		[]common.Address{kettleAttackerContract, kettleBuilderContract, buildEthBlockAddress})
	args := kettleBlockArgs(nextKettleSlot(), 0xab, 0x02, 0x43)
	ret, err := h.callContract(kettleAttackerContract, kettleAttackerOrigin, args, bid.Id)
	h.requireRefusal(ret, err)
}

func TestKettleBuilderBid_DirectPrecompileCallWithAnyPeekerCannotSign(t *testing.T) {
	h := newKettleHarness(t)
	h.allowBuilder(t)
	bid := h.storeBid(kettleAttackerContract, "default:v0:ethBundles", "default:v0:ethBundles", h.bundle,
		[]common.Address{suave.AllowedPeekerAny})
	args := kettleBlockArgs(nextKettleSlot(), 0xac, 0x03, 0x44)
	ret, err := h.callPrecompile(kettleAttackerOrigin, args, bid.Id)
	h.requireRefusal(ret, err)
}

func TestKettleBuilderBid_RunConfidentialUntrustedCallerCannotSign(t *testing.T) {
	h := newKettleHarness(t)
	h.allowBuilder(t)
	bid := h.attackerBid("default:v0:ethBundles", "default:v0:ethBundles")
	args := kettleBlockArgs(nextKettleSlot(), 0xad, 0x04, 0x45)
	// RunConfidential is not what the EVM calls. Its ABI type assert currently
	// panics before signing. Once that assert matches the unpacked arguments,
	// the call still must not return a kettle signature.
	defer func() {
		if recovered := recover(); recovered != nil {
			if !bytes.Contains([]byte(fmt.Sprint(recovered)), []byte("interface conversion")) {
				t.Fatalf("RunConfidential panicked before the signing check: %v", recovered)
			}
		}
	}()
	ret, err := (&buildEthBlock{}).RunConfidential(h.callerContext(kettleAttackerContract), h.pack(args, bid.Id))
	h.requireRefusal(ret, err)
}

func TestKettleBuilderBid_MevShareAndMergedBidsAreRestricted(t *testing.T) {
	h := newKettleHarness(t)
	h.allowBuilder(t)

	t.Run("unmatched", func(t *testing.T) {
		h.t = t
		unmatched := h.attackerBid("mevshare:v0:unmatchedBundles", "mevshare:v0:ethBundles")
		args := kettleBlockArgs(nextKettleSlot(), 0xae, 0x05, 0x46)
		ret, err := h.callContract(kettleAttackerContract, kettleAttackerOrigin, args, unmatched.Id)
		h.requireRefusal(ret, err)
	})

	t.Run("merged", func(t *testing.T) {
		h.t = t
		inner := h.attackerBid("default:v0:ethBundles", "default:v0:ethBundles")
		mergedIDs, err := bidIdsAbi.Inputs.Pack([][16]byte{inner.Id})
		require.NoError(t, err)
		outer := h.storeBid(kettleAttackerContract, "default:v0:mergedBids", "default:v0:mergedBids", mergedIDs,
			[]common.Address{kettleAttackerContract, buildEthBlockAddress})
		args := kettleBlockArgs(nextKettleSlot(), 0xaf, 0x06, 0x47)
		ret, err := h.callContract(kettleAttackerContract, kettleAttackerOrigin, args, outer.Id)
		h.requireRefusal(ret, err)
	})

	t.Run("match", func(t *testing.T) {
		h.t = t
		user := h.storeBid(kettleAttackerContract, "mevshare:v0:unmatchedBundles", "mevshare:v0:ethBundles", h.bundle,
			[]common.Address{kettleAttackerContract, buildEthBlockAddress})
		match := h.storeBid(kettleAttackerContract, "mevshare:v0:unmatchedBundles", "mevshare:v0:ethBundles", h.bundle,
			[]common.Address{kettleAttackerContract, buildEthBlockAddress})
		matchedIDs, err := bidIdsAbi.Inputs.Pack([][16]byte{user.Id, match.Id})
		require.NoError(t, err)
		matched := h.storeBid(kettleAttackerContract, "mevshare:v0:matchBids", "mevshare:v0:mergedBids", matchedIDs,
			[]common.Address{kettleAttackerContract, buildEthBlockAddress})
		args := kettleBlockArgs(nextKettleSlot(), 0xb0, 0x07, 0x48)
		ret, err := h.callContract(kettleAttackerContract, kettleAttackerOrigin, args, matched.Id)
		h.requireRefusal(ret, err)
	})
}

func TestKettleBuilderBid_UnsetBuilderRejectsConfiguredContract(t *testing.T) {
	h := newKettleHarness(t)
	t.Setenv(suaveBuilderContractEnv, "")
	if _, ok := os.LookupEnv(suaveBuilderContractEnv); ok && os.Getenv(suaveBuilderContractEnv) != "" {
		t.Fatalf("test failed to clear %s", suaveBuilderContractEnv)
	}
	bid := h.builderBid("default:v0:ethBundles", "default:v0:ethBundles")
	args := kettleBlockArgs(nextKettleSlot(), 0xb1, 0x08, 0x49)
	ret, err := h.callContract(kettleBuilderContract, kettleAttackerOrigin, args, bid.Id)
	h.requireRefusal(ret, err)
}

func TestKettleBuilderBid_ConfiguredBuilderSignsOncePerSlot(t *testing.T) {
	h := newKettleHarness(t)
	h.allowBuilder(t)
	slot := nextKettleSlot()

	firstBid := h.builderBid("default:v0:ethBundles", "default:v0:ethBundles")
	firstArgs := kettleBlockArgs(slot, 0xc1, 0x11, 0x51)
	ret, err := h.callContract(kettleBuilderContract, kettleAttackerOrigin, firstArgs, firstBid.Id)
	first := h.requireSigned(ret, err, firstArgs)

	secondBid := h.builderBid("default:v0:ethBundles", "default:v0:ethBundles")
	secondArgs := kettleBlockArgs(slot, 0xc1, 0x22, 0x52)
	ret, err = h.callContract(kettleBuilderContract, kettleAttackerOrigin, secondArgs, secondBid.Id)
	h.requireRefusal(ret, err)

	otherBid := h.builderBid("default:v0:ethBundles", "default:v0:ethBundles")
	otherArgs := kettleBlockArgs(nextKettleSlot(), 0xc2, 0x33, 0x53)
	ret, err = h.callContract(kettleBuilderContract, kettleAttackerOrigin, otherArgs, otherBid.Id)
	other := h.requireSigned(ret, err, otherArgs)
	if bytes.Equal(first.Message.BlockHash[:], other.Message.BlockHash[:]) {
		t.Fatalf("distinct slots produced the same signed block hash")
	}
}

func TestKettleBuilderBid_SlotReservationIsSharedAcrossEntryPoints(t *testing.T) {
	h := newKettleHarness(t)
	h.allowBuilder(t)
	slot := nextKettleSlot()

	firstBid := h.builderBid("default:v0:ethBundles", "default:v0:ethBundles")
	firstArgs := kettleBlockArgs(slot, 0xd1, 0x41, 0x61)
	ret, err := h.callRunImpl(kettleBuilderContract, firstArgs, firstBid.Id)
	h.requireSigned(ret, err, firstArgs)

	secondBid := h.builderBid("default:v0:ethBundles", "default:v0:ethBundles")
	secondArgs := kettleBlockArgs(slot, 0xd1, 0x42, 0x62)
	ret, err = h.callContract(kettleBuilderContract, kettleAttackerOrigin, secondArgs, secondBid.Id)
	h.requireRefusal(ret, err)

	// The opposite order: a signature returned through the EVM must also
	// stop a later runImpl call for that slot.
	slot = nextKettleSlot()
	thirdBid := h.builderBid("default:v0:ethBundles", "default:v0:ethBundles")
	thirdArgs := kettleBlockArgs(slot, 0xd2, 0x43, 0x63)
	ret, err = h.callContract(kettleBuilderContract, kettleAttackerOrigin, thirdArgs, thirdBid.Id)
	h.requireSigned(ret, err, thirdArgs)

	fourthBid := h.builderBid("default:v0:ethBundles", "default:v0:ethBundles")
	fourthArgs := kettleBlockArgs(slot, 0xd2, 0x44, 0x64)
	ret, err = h.callRunImpl(kettleBuilderContract, fourthArgs, fourthBid.Id)
	h.requireRefusal(ret, err)
}

func TestKettleBuilderBid_OverlappingCallsSignAtMostOnce(t *testing.T) {
	h := newKettleHarness(t)
	h.allowBuilder(t)
	h.payload.delay = 200 * time.Millisecond
	slot := nextKettleSlot()

	type result struct {
		ret []byte
		err error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		bid := h.builderBid("default:v0:ethBundles", "default:v0:ethBundles")
		args := kettleBlockArgs(slot, 0xe1, byte(0x70+i), byte(0x80+i))
		wg.Add(1)
		go func(i int, bidID types.BidId, args types.BuildBlockArgs) {
			defer wg.Done()
			ret, err := h.callContract(kettleBuilderContract, kettleAttackerOrigin, args, bidID)
			results[i] = result{ret, err}
		}(i, bid.Id, args)
	}
	wg.Wait()

	signatures := 0
	var signed []*builderCapella.SubmitBlockRequest
	for _, result := range results {
		req, ok := h.verifyingBid(result.ret)
		if !ok {
			continue
		}
		signatures++
		signed = append(signed, req)
	}
	if signatures != 1 {
		detail := "none"
		if len(signed) == 2 {
			detail = "two different payloads"
			if bytes.Equal(signed[0].Message.BlockHash[:], signed[1].Message.BlockHash[:]) {
				detail = "two signatures over the same block hash"
			}
		}
		t.Fatalf("overlapping buildEthBlock calls for slot %d returned %d kettle signatures (%s)", slot, signatures, detail)
	}
}
