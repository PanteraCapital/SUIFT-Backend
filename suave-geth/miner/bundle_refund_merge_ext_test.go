package miner_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/suave/artifacts"
	suave "github.com/ethereum/go-ethereum/suave/core"
	"github.com/flashbots/go-boost-utils/bls"
)

// TestMatchedBundleRefundExcludesSearcherProfit drives the real match-merge
// in buildEthBlock and the real bundle builder. A user bundle whose JSON
// percent is 1 must not be paid the searcher's coinbase profit when the
// searcher's transactions are merged onto it.

type mergeChain struct {
	chain  *core.BlockChain
	pool   *txpool.TxPool
	miner  *miner.Miner
	engine *ethash.Ethash
}

func (m *mergeChain) close() {
	m.miner.Close()
	m.pool.Stop()
	m.engine.Close()
}

func (m *mergeChain) BlockChain() *core.BlockChain { return m.chain }
func (m *mergeChain) TxPool() *txpool.TxPool       { return m.pool }

func newMergeChain(t *testing.T, fund []common.Address) *mergeChain {
	t.Helper()
	alloc := core.GenesisAlloc{}
	rich := new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))
	for _, addr := range fund {
		alloc[addr] = core.GenesisAccount{Balance: new(big.Int).Set(rich)}
	}
	gspec := &core.Genesis{Config: params.TestChainConfig, Alloc: alloc}
	db := rawdb.NewMemoryDatabase()
	ethEngine := ethash.NewFaker()
	chain, err := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, gspec, nil, ethEngine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	poolCfg := txpool.DefaultConfig
	poolCfg.Journal = ""
	pool := txpool.NewTxPool(poolCfg, params.TestChainConfig, chain)
	cfg := miner.DefaultConfig
	cfg.GasCeil = 30_000_000
	m := &mergeChain{
		chain:  chain,
		pool:   pool,
		engine: ethEngine,
		miner:  miner.New(&mergeChain{chain: chain, pool: pool}, &cfg, params.TestChainConfig, new(event.TypeMux), ethEngine, nil),
	}
	return m
}

type memBidStore struct {
	bids map[types.BidId]suave.Bid
	data map[string][]byte
}

func newMemBidStore() *memBidStore {
	return &memBidStore{
		bids: map[types.BidId]suave.Bid{},
		data: map[string][]byte{},
	}
}

func bidKey(id types.BidId, key string) string {
	return string(id[:]) + ":" + key
}

func (m *memBidStore) InitializeBid(bid types.Bid) (types.Bid, error) { return bid, nil }
func (m *memBidStore) Store(id suave.BidId, caller common.Address, key string, value []byte) (suave.Bid, error) {
	m.data[bidKey(id, key)] = append([]byte(nil), value...)
	return m.bids[id], nil
}
func (m *memBidStore) Retrieve(id types.BidId, caller common.Address, key string) ([]byte, error) {
	value, ok := m.data[bidKey(id, key)]
	if !ok {
		return nil, errors.New("missing")
	}
	return append([]byte(nil), value...), nil
}
func (m *memBidStore) FetchBidById(id suave.BidId) (suave.Bid, error) {
	bid, ok := m.bids[id]
	if !ok {
		return suave.Bid{}, errors.New("missing bid")
	}
	return bid, nil
}
func (m *memBidStore) FetchBidsByProtocolAndBlock(uint64, string) []suave.Bid { return nil }

func (m *memBidStore) putBid(bid suave.Bid) {
	m.bids[bid.Id] = bid
}

func (m *memBidStore) put(id types.BidId, key string, value []byte) {
	m.data[bidKey(id, key)] = append([]byte(nil), value...)
}

type recordingBuilder struct {
	miner *miner.Miner
	block *types.Block
	err   error
}

func (r *recordingBuilder) BuildEthBlock(ctx context.Context, args *suave.BuildBlockArgs, txs types.Transactions) (*engine.ExecutionPayloadEnvelope, error) {
	return nil, errors.New("unused")
}

func (r *recordingBuilder) BuildEthBlockFromBundles(ctx context.Context, args *suave.BuildBlockArgs, bundles []types.SBundle) (*engine.ExecutionPayloadEnvelope, error) {
	block, profit, err := r.miner.BuildBlockFromBundles(ctx, args, bundles)
	r.block = block
	r.err = err
	if err != nil {
		return nil, err
	}
	return engine.BlockToExecutableData(block, profit), nil
}

func (r *recordingBuilder) Call(context.Context, common.Address, []byte) ([]byte, error) {
	return nil, errors.New("unused")
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signPay(t *testing.T, key *ecdsa.PrivateKey, nonce uint64, to common.Address, gasPrice *big.Int) *types.Transaction {
	t.Helper()
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    big.NewInt(1),
		Gas:      params.TxGas,
		GasPrice: gasPrice,
	}), types.LatestSigner(params.TestChainConfig), key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func bundleBytes(t *testing.T, txs types.Transactions, percent *int) []byte {
	t.Helper()
	raw, err := json.Marshal(&types.SBundle{Txs: txs, RefundPercent: percent})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func packBidIDs(t *testing.T, ids ...types.BidId) []byte {
	t.Helper()
	typ, err := abi.NewType("bytes16[]", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := abi.Arguments{{Type: typ}}.Pack(ids)
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func paidTo(block *types.Block, to common.Address) *big.Int {
	sum := new(big.Int)
	for _, tx := range block.Transactions() {
		if tx.To() != nil && *tx.To() == to && tx.Value().Cmp(big.NewInt(1)) > 0 {
			sum.Add(sum, tx.Value())
		}
	}
	return sum
}

func hasTx(block *types.Block, want *types.Transaction) bool {
	for _, tx := range block.Transactions() {
		if tx.Hash() == want.Hash() {
			return true
		}
	}
	return false
}

func TestMatchedBundleRefundExcludesSearcherProfit(t *testing.T) {
	user := mustKey(t)
	searcher := mustKey(t)
	other := mustKey(t)
	userAddr := crypto.PubkeyToAddress(user.PublicKey)
	searcherAddr := crypto.PubkeyToAddress(searcher.PublicKey)
	otherAddr := crypto.PubkeyToAddress(other.PublicKey)
	proposer := common.HexToAddress("0x3333333333333333333333333333333333333333")
	sink := common.HexToAddress("0x4444444444444444444444444444444444444444")

	env := newMergeChain(t, []common.Address{userAddr, searcherAddr, otherAddr})
	defer env.close()

	baseFee := misc.CalcBaseFee(env.chain.Config(), env.chain.CurrentHeader())
	userPrice := new(big.Int).Mul(baseFee, big.NewInt(80))
	searcherPrice := new(big.Int).Mul(baseFee, big.NewInt(2000))
	userTxs := types.Transactions{
		signPay(t, user, 0, sink, userPrice),
		signPay(t, user, 1, sink, userPrice),
	}
	searcherTxs := types.Transactions{
		signPay(t, searcher, 0, sink, searcherPrice),
		signPay(t, searcher, 1, sink, searcherPrice),
	}
	otherTx := signPay(t, other, 0, sink, userPrice)

	head := env.chain.CurrentHeader()
	args := &types.BuildBlockArgs{
		Parent:         head.Hash(),
		Timestamp:      head.Time + 12,
		FeeRecipient:   proposer,
		GasLimit:       30_000_000,
		ProposerPubkey: make([]byte, 48),
	}
	_, userProfit, err := env.miner.BuildBlockFromTxs(context.Background(), args, userTxs)
	if err != nil {
		t.Fatalf("user profit: %v", err)
	}
	_, searcherProfit, err := env.miner.BuildBlockFromTxs(context.Background(), args, searcherTxs)
	if err != nil {
		t.Fatalf("searcher profit: %v", err)
	}
	if searcherProfit.Cmp(new(big.Int).Mul(userProfit, big.NewInt(10))) <= 0 {
		t.Fatalf("searcher profit %s is not larger than the user profit %s", searcherProfit, userProfit)
	}

	percent := 1
	userID := types.BidId{1}
	matchID := types.BidId{2}
	otherID := types.BidId{3}
	blockID := types.BidId{4}
	allow := []common.Address{suave.AllowedPeekerAny}

	store := newMemBidStore()
	store.putBid(suave.Bid{Id: userID, Version: "mevshare:v0:unmatchedBundles", AllowedPeekers: allow})
	store.putBid(suave.Bid{Id: matchID, Version: "mevshare:v0:matchBids", AllowedPeekers: allow})
	store.putBid(suave.Bid{Id: otherID, Version: "default:v0:ethBundles", AllowedPeekers: allow})
	store.put(userID, "mevshare:v0:ethBundles", bundleBytes(t, userTxs, &percent))
	store.put(matchID, "mevshare:v0:ethBundles", bundleBytes(t, searcherTxs, nil))
	store.put(matchID, "mevshare:v0:mergedBids", packBidIDs(t, userID, matchID))
	store.put(otherID, "default:v0:ethBundles", bundleBytes(t, types.Transactions{otherTx}, nil))
	store.put(blockID, "default:v0:mergedBids", packBidIDs(t, matchID, otherID))

	sk, _, err := bls.GenerateNewKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingBuilder{miner: env.miner}
	caller := artifacts.SuaveMethods["buildEthBlock"]
	chainCfg := *params.TestChainConfig
	chainCfg.SuaveBlock = big.NewInt(0)
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatal(err)
	}
	evm := vm.NewConfidentialEVM(vm.SuaveContext{
		Backend: &vm.SuaveExecutionBackend{
			EthBlockSigningKey:     sk,
			ConfidentialStore:      store,
			ConfidentialEthBackend: recorder,
		},
		CallerStack: []*common.Address{&caller},
	}, vm.BlockContext{
		CanTransfer: func(vm.StateDB, common.Address, *big.Int) bool { return true },
		Transfer:    func(vm.StateDB, common.Address, common.Address, *big.Int) {},
		BlockNumber: big.NewInt(1),
		Random:      &common.Hash{},
	}, vm.TxContext{}, statedb, &chainCfg, vm.Config{IsConfidential: true})

	packed, err := artifacts.SuaveAbi.Methods["buildEthBlock"].Inputs.Pack(*args, blockID, "mevshare:v0")
	if err != nil {
		t.Fatalf("pack buildEthBlock: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("matched block build panicked: %v", r)
		}
	}()
	if _, _, err := evm.Call(vm.AccountRef(caller), artifacts.SuaveMethods["buildEthBlock"], packed, 1_000_000, big.NewInt(0)); err != nil && recorder.block == nil {
		t.Fatalf("buildEthBlock: %v", err)
	}
	block := recorder.block
	if block == nil {
		t.Fatalf("builder returned no block: %v", recorder.err)
	}
	for _, tx := range append(append(types.Transactions{}, userTxs...), append(searcherTxs, otherTx)...) {
		if !hasTx(block, tx) {
			t.Fatalf("built block is missing transaction %s", tx.Hash())
		}
	}

	paid := paidTo(block, userAddr)
	onePercent := new(big.Int).Div(new(big.Int).Set(userProfit), big.NewInt(100))
	if paid.Cmp(onePercent) > 0 {
		t.Fatalf("user bundle percent 1 paid %s to the user, more than 1%% of the user's own profit %s (searcher profit %s was merged onto the bundle)", paid, userProfit, searcherProfit)
	}
	if paidTo(block, searcherAddr).Sign() != 0 {
		t.Fatalf("searcher received a refund of %s from the user's percent", paidTo(block, searcherAddr))
	}
	proposerPaid := paidTo(block, proposer)
	halfSearcher := new(big.Int).Div(new(big.Int).Set(searcherProfit), big.NewInt(2))
	if proposerPaid.Cmp(halfSearcher) < 0 {
		t.Fatalf("proposer payment %s is below half of the searcher's coinbase profit %s", proposerPaid, searcherProfit)
	}
}
