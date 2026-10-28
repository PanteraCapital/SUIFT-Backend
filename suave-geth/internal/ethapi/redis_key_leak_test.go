package ethapi

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/suave/artifacts"
	suave "github.com/ethereum/go-ethereum/suave/core"
	"github.com/ethereum/go-ethereum/suave/cstore"
	"github.com/stretchr/testify/require"
)

// These tests send a confidential transaction through eth_sendRawTransaction.
// The contract staticcalls a precompile and reverts with that call's return
// data, which is the same path Suave.confidentialRetrieve uses when the
// precompile returns an error.

func TestSendRawTransactionMissingRetrieveDoesNotDiscloseRedisKeys(t *testing.T) {
	env := newLeakEnv(t)
	bid := env.seedBids(t, []common.Address{env.contract})

	err := env.send(t, artifacts.SuaveMethods["confidentialRetrieve"],
		mustPack(t, "confidentialRetrieve", bid.Id, "missing-key"))
	env.assertClean(t, err)
}

func TestSendRawTransactionBuildEthBlockMissDoesNotDiscloseRedisKeys(t *testing.T) {
	env := newLeakEnv(t)
	precompile := artifacts.SuaveMethods["buildEthBlock"]
	bid := env.seedBids(t, []common.Address{env.contract, precompile})

	args := struct {
		Slot           uint64
		ProposerPubkey []byte
		Parent         common.Hash
		Timestamp      uint64
		FeeRecipient   common.Address
		GasLimit       uint64
		Random         common.Hash
		Withdrawals    []struct {
			Index     uint64
			Validator uint64
			Address   common.Address
			Amount    uint64
		}
	}{
		ProposerPubkey: []byte{0x01},
		GasLimit:       1,
		Withdrawals: []struct {
			Index     uint64
			Validator uint64
			Address   common.Address
			Amount    uint64
		}{},
	}
	err := env.send(t, precompile, mustPack(t, "buildEthBlock", args, bid.Id, "default:v0:ethBundles"))
	env.assertClean(t, err)
}

func TestSendRawTransactionFillMevShareMissDoesNotDiscloseRedisKeys(t *testing.T) {
	env := newLeakEnv(t)
	precompile := artifacts.SuaveMethods["fillMevShareBundle"]
	bid := env.seedBids(t, []common.Address{env.contract, precompile})

	err := env.send(t, precompile, mustPack(t, "fillMevShareBundle", bid.Id))
	env.assertClean(t, err)
}

type leakEnv struct {
	api      *TransactionAPI
	mr       *miniredis.Miniredis
	store    *cstore.RedisStoreBackend
	commands *rpcCommandLog
	key      *ecdsa.PrivateKey
	sender   common.Address
	contract common.Address
	secret   string
	victimID suave.BidId
}

func newLeakEnv(t *testing.T) *leakEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	commands := newRPCCommandLog(mr)
	store, err := cstore.NewRedisStoreBackend(mr.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Stop() })

	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	sender := crypto.PubkeyToAddress(key.PublicKey)

	ks := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	acct, err := ks.ImportECDSA(key, "pass")
	require.NoError(t, err)
	require.NoError(t, ks.Unlock(acct, "pass"))
	manager := accounts.NewManager(&accounts.Config{InsecureUnlockAllowed: true}, ks)
	t.Cleanup(func() { manager.Close() })

	contract := common.HexToAddress("0xC0FFEE0000000000000000000000000000000001")
	genesis := &core.Genesis{
		Config:   params.AllEthashProtocolChanges,
		GasLimit: 30_000_000,
		Alloc: core.GenesisAlloc{
			sender: {Balance: new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(100))},
		},
	}
	base := newTestBackend(t, 1, genesis, func(int, *core.BlockGen) {})
	engine := cstore.NewConfidentialStoreEngine(store, cstore.MockTransport{}, cstore.MockSigner{}, cstore.MockChainSigner{})
	backend := &leakBackend{
		testBackend: *base,
		engine:      engine,
		manager:     manager,
		contract:    contract,
		sender:      sender,
	}
	return &leakEnv{
		api:      NewTransactionAPI(backend, new(AddrLocker)),
		mr:       mr,
		store:    store,
		commands: commands,
		key:      key,
		sender:   sender,
		contract: contract,
		secret:   "VICTIM-PAYLOAD-VALUE-9f3a",
	}
}

func (e *leakEnv) seedBids(t *testing.T, peekers []common.Address) suave.Bid {
	t.Helper()
	attacker := suave.Bid{
		Id:                  mustBidID("attacker-bid-id!"),
		DecryptionCondition: 10,
		AllowedPeekers:      peekers,
		Version:             "default:v0:ethBundles",
	}
	victim := suave.Bid{
		Id:                  mustBidID("victim-bid-id!!!"),
		DecryptionCondition: 10,
		AllowedPeekers:      []common.Address{common.HexToAddress("0x2222222222222222222222222222222222222222")},
		Version:             "default:v0:ethBundles",
	}
	require.NoError(t, e.store.InitializeBid(attacker))
	require.NoError(t, e.store.InitializeBid(victim))
	_, err := e.store.Store(attacker, e.contract, "attacker-owned-key", []byte("attacker-value"))
	require.NoError(t, err)
	_, err = e.store.Store(victim, victim.AllowedPeekers[0], "victim-secret-name", []byte(e.secret))
	require.NoError(t, err)
	e.victimID = victim.Id
	e.commands.mark()
	return attacker
}

func (e *leakEnv) send(t *testing.T, precompile common.Address, input []byte) error {
	t.Helper()
	e.commands.mark()
	ctx := context.Background()
	header, err := e.api.b.HeaderByNumber(ctx, rpc.LatestBlockNumber)
	require.NoError(t, err)
	require.NotNil(t, header)

	gasPrice := header.BaseFee
	if gasPrice == nil {
		gasPrice = big.NewInt(1)
	}
	gasPrice = new(big.Int).Add(gasPrice, big.NewInt(1_000_000_000))
	to := e.contract
	inner := &types.ConfidentialComputeRequest{
		ConfidentialComputeRecord: types.ConfidentialComputeRecord{
			Nonce:         0,
			GasPrice:      gasPrice,
			Gas:           8_000_000,
			To:            &to,
			Value:         big.NewInt(0),
			Data:          input,
			ExecutionNode: e.sender,
		},
	}
	signed, err := types.SignTx(types.NewTx(inner), types.LatestSigner(e.api.b.ChainConfig()), e.key)
	require.NoError(t, err)
	raw, err := signed.MarshalBinary()
	require.NoError(t, err)

	// The contract forwards calldata to the precompile and reverts with the
	// precompile return data. Install that code for this call.
	if backend, ok := e.api.b.(*leakBackend); ok {
		backend.code = revertWithPrecompileReturn(precompile)
	}

	_, err = e.api.SendRawTransaction(ctx, raw)
	return err
}

func (e *leakEnv) assertClean(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("eth_sendRawTransaction accepted a missing confidential read")
	}
	text := discloseRPCText(err)
	for _, key := range e.mr.Keys() {
		if strings.Contains(text, key) {
			t.Fatalf("eth_sendRawTransaction disclosed redis key %q\nresponse: %s", key, text)
		}
	}
	for _, forbidden := range []string{e.secret, "victim-secret-name", bidHex(e.victimID)} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("eth_sendRawTransaction disclosed %q\nresponse: %s", forbidden, text)
		}
	}
	cmds := e.commands.sinceMark()
	if scans := countRPCScans(cmds); scans != 0 {
		t.Fatalf("eth_sendRawTransaction scanned redis with %d KEYS/SCAN command(s): %v\nresponse: %s", scans, cmds, text)
	}
	if countRPCCmd(cmds, "GET") == 0 {
		t.Fatalf("eth_sendRawTransaction never reached the confidential store: %v\nresponse: %s", cmds, text)
	}
}

type leakBackend struct {
	testBackend
	engine   *cstore.ConfidentialStoreEngine
	manager  *accounts.Manager
	contract common.Address
	sender   common.Address
	code     []byte
}

func (b *leakBackend) AccountManager() *accounts.Manager { return b.manager }

func (b *leakBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	statedb, header, err := b.testBackend.StateAndHeaderByNumber(ctx, number)
	if err != nil || statedb == nil {
		return statedb, header, err
	}
	statedb.SetCode(b.contract, b.code)
	statedb.SetBalance(b.sender, new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(100)))
	return statedb, header, nil
}

func (b *leakBackend) SuaveContext(requestTx *types.Transaction, ccr *types.ConfidentialComputeRequest) vm.SuaveContext {
	return vm.SuaveContext{
		ConfidentialComputeRequestTx: requestTx,
		ConfidentialInputs:           ccr.ConfidentialInputs,
		CallerStack:                  []*common.Address{},
		Backend:                      &vm.SuaveExecutionBackend{},
	}
}

func (b *leakBackend) GetMEVM(ctx context.Context, msg *core.Message, statedb *state.StateDB, header *types.Header, vmConfig *vm.Config, blockCtx *vm.BlockContext, suaveCtx *vm.SuaveContext) (*vm.EVM, func() error, func() error) {
	if vmConfig == nil {
		vmConfig = b.chain.GetVMConfig()
	}
	txContext := core.NewEVMTxContext(msg)
	var context vm.BlockContext
	if blockCtx != nil {
		context = *blockCtx
	} else {
		context = core.NewEVMBlockContext(header, b.chain, nil)
	}
	suaveCtxCopy := *suaveCtx
	storeTransaction := b.engine.NewTransactionalStore(suaveCtx.ConfidentialComputeRequestTx)
	if suaveCtxCopy.Backend == nil {
		suaveCtxCopy.Backend = &vm.SuaveExecutionBackend{}
	}
	suaveCtxCopy.Backend.ConfidentialStore = storeTransaction
	return vm.NewConfidentialEVM(suaveCtxCopy, context, txContext, statedb, b.chain.Config(), *vmConfig), storeTransaction.Finalize, statedb.Error
}

type rpcCommandLog struct {
	mu   sync.Mutex
	cmds []string
	at   int
}

func newRPCCommandLog(mr *miniredis.Miniredis) *rpcCommandLog {
	log := &rpcCommandLog{}
	mr.Server().SetPreHook(func(_ *server.Peer, cmd string, _ ...string) bool {
		log.mu.Lock()
		log.cmds = append(log.cmds, strings.ToUpper(cmd))
		log.mu.Unlock()
		return false
	})
	return log
}

func (l *rpcCommandLog) mark() {
	l.mu.Lock()
	l.at = len(l.cmds)
	l.mu.Unlock()
}

func (l *rpcCommandLog) sinceMark() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.cmds)-l.at)
	copy(out, l.cmds[l.at:])
	return out
}

func revertWithPrecompileReturn(precompile common.Address) []byte {
	// Forwards all calldata to precompile via STATICCALL, then REVERTs with
	// the full return data. That is the interpreter path behind
	// `bytes memory data` in Suave.confidentialRetrieve.
	code := []byte{
		0x36,       // CALLDATASIZE
		0x60, 0x00, // PUSH1 0 dataOffset
		0x60, 0x00, // PUSH1 0 memOffset
		0x37, // CALLDATACOPY

		0x60, 0x00, // PUSH1 0 retSize
		0x60, 0x00, // PUSH1 0 retOffset
		0x36,       // CALLDATASIZE argsSize
		0x60, 0x00, // PUSH1 0 argsOffset
		0x73, // PUSH20 precompile
	}
	code = append(code, precompile.Bytes()...)
	code = append(code,
		0x5a, // GAS
		0xfa, // STATICCALL
		0x50, // POP success

		0x3d,       // RETURNDATASIZE
		0x60, 0x00, // PUSH1 0 dataOffset
		0x60, 0x00, // PUSH1 0 memOffset
		0x3e, // RETURNDATACOPY

		0x3d,       // RETURNDATASIZE
		0x60, 0x00, // PUSH1 0 offset
		0xfd, // REVERT
	)
	return code
}

func mustPack(t *testing.T, method string, args ...interface{}) []byte {
	t.Helper()
	packed, err := artifacts.SuaveAbi.Methods[method].Inputs.Pack(args...)
	require.NoError(t, err)
	return packed
}

func mustBidID(text string) suave.BidId {
	if len(text) != 16 {
		panic("bid id text must be 16 bytes")
	}
	var id suave.BidId
	copy(id[:], text)
	return id
}

func bidHex(id suave.BidId) string {
	return strings.TrimPrefix(hexutil.Encode(id[:]), "0x")
}

func discloseRPCText(err error) string {
	raw := err.Error()
	text := raw
	if i := strings.LastIndex(raw, "0x"); i >= 0 {
		if decoded, decErr := hexutil.Decode(raw[i:]); decErr == nil {
			text += "\n" + string(decoded)
		}
	}
	return text
}

func countRPCScans(cmds []string) int {
	return countRPCCmd(cmds, "KEYS") + countRPCCmd(cmds, "SCAN")
}

func countRPCCmd(cmds []string, want string) int {
	n := 0
	for _, cmd := range cmds {
		if cmd == want {
			n++
		}
	}
	return n
}
