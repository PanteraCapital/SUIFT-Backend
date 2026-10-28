package miner

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
)

// Bundle refund tests describe the behavior buildBlockFromBundles must have
// once the percent field is a share of that bundle's own coinbase profit.
// They fail while percent is used as a divisor, and while one bundle's
// failure aborts or crashes the whole build.

func newRefundWorker(t *testing.T, fund []common.Address) (*worker, *core.BlockChain, func()) {
	t.Helper()
	alloc := core.GenesisAlloc{}
	rich := new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))
	for _, addr := range fund {
		alloc[addr] = core.GenesisAccount{Balance: new(big.Int).Set(rich)}
	}
	gspec := &core.Genesis{Config: params.TestChainConfig, Alloc: alloc}
	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	chain, err := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, gspec, nil, engine, vm.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	pool := txpool.NewTxPool(testTxPoolConfig, params.TestChainConfig, chain)
	backend := &testWorkerBackend{db: db, chain: chain, txPool: pool, genesis: gspec}
	w := newWorker(testConfig, params.TestChainConfig, engine, backend, new(event.TypeMux), nil, false)
	return w, chain, func() {
		w.close()
		engine.Close()
		pool.Stop()
	}
}

func refundKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func refundSigner() types.Signer {
	return types.LatestSigner(params.TestChainConfig)
}

func signLegacyValue(t *testing.T, key *ecdsa.PrivateKey, nonce uint64, to common.Address, value, gasPrice *big.Int) *types.Transaction {
	t.Helper()
	tx, err := types.SignTx(types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &to,
		Value:    value,
		Gas:      params.TxGas,
		GasPrice: gasPrice,
	}), refundSigner(), key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func percentPtr(v int) *int { return &v }

// bundleJSON round-trips a bundle through the JSON encoding the builder stores
// and later unmarshals. The share is the "percent" field.
func bundleJSON(t *testing.T, txs types.Transactions, percent *int) types.SBundle {
	t.Helper()
	raw, err := json.Marshal(&types.SBundle{Txs: txs, RefundPercent: percent})
	if err != nil {
		t.Fatal(err)
	}
	if percent != nil && !bytes.Contains(raw, []byte(fmt.Sprintf(`"percent":%d`, *percent))) {
		t.Fatalf("bundle JSON did not encode percent %d: %s", *percent, raw)
	}
	var out types.SBundle
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func refundArgs(chain *core.BlockChain, proposer common.Address) *types.BuildBlockArgs {
	head := chain.CurrentHeader()
	return &types.BuildBlockArgs{
		Parent:       head.Hash(),
		Timestamp:    head.Time + 12,
		FeeRecipient: proposer,
		GasLimit:     30_000_000,
	}
}

func childBaseFee(chain *core.BlockChain) *big.Int {
	return misc.CalcBaseFee(chain.Config(), chain.CurrentHeader())
}

func grossProfit(t *testing.T, w *worker, args *types.BuildBlockArgs, txs types.Transactions) *big.Int {
	t.Helper()
	_, profit, err := w.buildBlockFromTxs(context.Background(), args, txs)
	if err != nil {
		t.Fatalf("measure profit: %v", err)
	}
	return profit
}

func buildBundles(t *testing.T, w *worker, args *types.BuildBlockArgs, bundles []types.SBundle) (*types.Block, *big.Int) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("buildBlockFromBundles panicked: %v", r)
		}
	}()
	block, profit, err := w.buildBlockFromBundles(context.Background(), args, bundles)
	if err != nil {
		t.Fatalf("buildBlockFromBundles: %v", err)
	}
	if block == nil {
		t.Fatal("buildBlockFromBundles returned no block")
	}
	return block, profit
}

// weiPaidTo sums payments in the block to `to` above the 1 wei sent by the
// bundle's own transfers. Those larger payments are the builder's refunds.
func weiPaidTo(block *types.Block, to common.Address) *big.Int {
	sum := new(big.Int)
	for _, tx := range block.Transactions() {
		if tx.To() != nil && *tx.To() == to && tx.Value().Cmp(big.NewInt(1)) > 0 {
			sum.Add(sum, tx.Value())
		}
	}
	return sum
}

func blockHasTx(block *types.Block, want *types.Transaction) bool {
	for _, tx := range block.Transactions() {
		if tx.Hash() == want.Hash() {
			return true
		}
	}
	return false
}

func assertPercentShare(t *testing.T, payment, profit *big.Int, percent int64, baseFee *big.Int) {
	t.Helper()
	share := new(big.Int).Mul(new(big.Int).Set(profit), big.NewInt(percent))
	share.Div(share, big.NewInt(100))
	if payment.Cmp(share) > 0 {
		t.Fatalf("refund %s exceeds %d%% of this bundle's coinbase profit %s", payment, percent, profit)
	}
	// A payment transaction spends gas. Allow a few reserved transfers of slack
	// under the percentage, and nothing above it.
	slack := new(big.Int).Mul(new(big.Int).Set(baseFee), big.NewInt(28000*4))
	min := new(big.Int).Sub(share, slack)
	if min.Sign() < 0 {
		min.SetInt64(0)
	}
	if payment.Cmp(min) < 0 {
		t.Fatalf("refund %s is below %d%% of profit %s minus transfer slack %s", payment, percent, profit, slack)
	}
}

func TestRefundPercentIsPercentageOfBundleProfit(t *testing.T) {
	user := refundKey(t)
	userAddr := crypto.PubkeyToAddress(user.PublicKey)
	proposer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sink := common.HexToAddress("0x2222222222222222222222222222222222222222")
	w, chain, cleanup := newRefundWorker(t, []common.Address{userAddr})
	defer cleanup()

	args := refundArgs(chain, proposer)
	baseFee := childBaseFee(chain)
	gasPrice := new(big.Int).Mul(baseFee, big.NewInt(80))
	txs := types.Transactions{
		signLegacyValue(t, user, 0, sink, big.NewInt(1), gasPrice),
		signLegacyValue(t, user, 1, sink, big.NewInt(1), gasPrice),
	}
	profit := grossProfit(t, w, args, txs)
	if profit.Sign() <= 0 {
		t.Fatalf("bundle produced no coinbase profit: %s", profit)
	}

	for _, percent := range []int{50, 90} {
		percent := percent
		t.Run(jsonPercentName(percent), func(t *testing.T) {
			bundle := bundleJSON(t, txs, percentPtr(percent))
			if bundle.RefundPercent == nil || *bundle.RefundPercent != percent {
				t.Fatalf("JSON percent = %v, want %d", bundle.RefundPercent, percent)
			}
			block, _ := buildBundles(t, w, args, []types.SBundle{bundle})
			paid := weiPaidTo(block, userAddr)
			assertPercentShare(t, paid, profit, int64(percent), block.BaseFee())
			proposerPaid := weiPaidTo(block, proposer)
			if proposerPaid.Sign() <= 0 {
				t.Fatalf("proposer payment = %s, want the remainder of the bundle profit", proposerPaid)
			}
		})
	}
}

func jsonPercentName(percent int) string {
	return "percent_" + big.NewInt(int64(percent)).String()
}

func TestRefundPercentOneDoesNotCaptureBundleProfit(t *testing.T) {
	user := refundKey(t)
	userAddr := crypto.PubkeyToAddress(user.PublicKey)
	other := refundKey(t)
	otherAddr := crypto.PubkeyToAddress(other.PublicKey)
	proposer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sink := common.HexToAddress("0x2222222222222222222222222222222222222222")
	w, chain, cleanup := newRefundWorker(t, []common.Address{userAddr, otherAddr})
	defer cleanup()

	args := refundArgs(chain, proposer)
	baseFee := childBaseFee(chain)
	gasPrice := new(big.Int).Mul(baseFee, big.NewInt(80))
	txs := types.Transactions{
		signLegacyValue(t, user, 0, sink, big.NewInt(1), gasPrice),
		signLegacyValue(t, user, 1, sink, big.NewInt(1), gasPrice),
	}
	// Another bundle keeps the proposer payment positive even if the refund
	// tries to take the whole first bundle. The first sender still must not
	// receive more than 1% of their own bundle.
	profit := grossProfit(t, w, args, txs)
	otherTx := signLegacyValue(t, other, 0, sink, big.NewInt(1), gasPrice)

	block, _ := buildBundles(t, w, args, []types.SBundle{
		bundleJSON(t, txs, percentPtr(1)),
		bundleJSON(t, types.Transactions{otherTx}, nil),
	})
	paid := weiPaidTo(block, userAddr)
	share := new(big.Int).Div(new(big.Int).Set(profit), big.NewInt(100))
	if paid.Cmp(share) > 0 {
		t.Fatalf("percent 1 refunded %s to the bundle sender, which is more than 1%% of bundle profit %s", paid, profit)
	}
	if !blockHasTx(block, otherTx) {
		t.Fatal("the other bundle was dropped")
	}
	if weiPaidTo(block, proposer).Sign() <= 0 {
		t.Fatal("proposer was not paid")
	}
}

func TestNonPositivePercentPaysNoRefund(t *testing.T) {
	user := refundKey(t)
	userAddr := crypto.PubkeyToAddress(user.PublicKey)
	other := refundKey(t)
	otherAddr := crypto.PubkeyToAddress(other.PublicKey)
	proposer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sink := common.HexToAddress("0x2222222222222222222222222222222222222222")
	w, chain, cleanup := newRefundWorker(t, []common.Address{userAddr, otherAddr})
	defer cleanup()

	args := refundArgs(chain, proposer)
	baseFee := childBaseFee(chain)
	gasPrice := new(big.Int).Mul(baseFee, big.NewInt(80))
	userTxs := types.Transactions{
		signLegacyValue(t, user, 0, sink, big.NewInt(1), gasPrice),
		signLegacyValue(t, user, 1, sink, big.NewInt(1), gasPrice),
	}
	otherTx := signLegacyValue(t, other, 0, sink, big.NewInt(1), gasPrice)

	for _, percent := range []int{0, -1, 200} {
		percent := percent
		t.Run(jsonPercentName(percent), func(t *testing.T) {
			block, _ := buildBundles(t, w, args, []types.SBundle{
				bundleJSON(t, userTxs, percentPtr(percent)),
				bundleJSON(t, types.Transactions{otherTx}, nil),
			})
			if paid := weiPaidTo(block, userAddr); paid.Sign() != 0 {
				t.Fatalf("percent %d refunded %s; non-positive and out-of-range percents must not be paid", percent, paid)
			}
			if !blockHasTx(block, otherTx) {
				t.Fatal("a bad percent aborted the block and dropped the other bundle")
			}
		})
	}
}

func TestZeroProfitRefundDoesNotAbortBlock(t *testing.T) {
	user := refundKey(t)
	userAddr := crypto.PubkeyToAddress(user.PublicKey)
	other := refundKey(t)
	otherAddr := crypto.PubkeyToAddress(other.PublicKey)
	proposer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sink := common.HexToAddress("0x2222222222222222222222222222222222222222")
	w, chain, cleanup := newRefundWorker(t, []common.Address{userAddr, otherAddr})
	defer cleanup()

	args := refundArgs(chain, proposer)
	baseFee := childBaseFee(chain)
	// gasPrice equal to the base fee leaves the coinbase with no tip, so
	// profit/percent minus the transfer cost is negative.
	noTip := types.Transactions{
		signLegacyValue(t, user, 0, sink, big.NewInt(1), baseFee),
		signLegacyValue(t, user, 1, sink, big.NewInt(1), baseFee),
	}
	otherTx := signLegacyValue(t, other, 0, sink, big.NewInt(1), new(big.Int).Mul(baseFee, big.NewInt(80)))

	block, _ := buildBundles(t, w, args, []types.SBundle{
		bundleJSON(t, noTip, percentPtr(1)),
		bundleJSON(t, types.Transactions{otherTx}, nil),
	})
	if !blockHasTx(block, otherTx) {
		t.Fatal("a non-positive refund aborted the block")
	}
	if paid := weiPaidTo(block, userAddr); paid.Sign() > 0 {
		t.Fatalf("zero-profit bundle refunded %s", paid)
	}
	if weiPaidTo(block, proposer).Sign() <= 0 {
		t.Fatal("proposer was not paid from the remaining bundle")
	}
}

func TestFailingBundleDoesNotAbortBlock(t *testing.T) {
	user := refundKey(t)
	userAddr := crypto.PubkeyToAddress(user.PublicKey)
	other := refundKey(t)
	otherAddr := crypto.PubkeyToAddress(other.PublicKey)
	proposer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	sink := common.HexToAddress("0x2222222222222222222222222222222222222222")
	w, chain, cleanup := newRefundWorker(t, []common.Address{userAddr, otherAddr})
	defer cleanup()

	args := refundArgs(chain, proposer)
	baseFee := childBaseFee(chain)
	gasPrice := new(big.Int).Mul(baseFee, big.NewInt(80))
	// Nonce 5 is not the account nonce, so this bundle cannot be applied.
	bad := signLegacyValue(t, user, 5, sink, big.NewInt(1), gasPrice)
	good := signLegacyValue(t, other, 0, sink, big.NewInt(1), gasPrice)

	block, _ := buildBundles(t, w, args, []types.SBundle{
		bundleJSON(t, types.Transactions{bad}, nil),
		bundleJSON(t, types.Transactions{good}, nil),
	})
	if blockHasTx(block, bad) {
		t.Fatal("invalid transaction was included")
	}
	if !blockHasTx(block, good) {
		t.Fatal("one invalid bundle aborted the block")
	}
}
