package cstore

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2/server"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	suave "github.com/ethereum/go-ethereum/suave/core"
	"github.com/stretchr/testify/require"
)

// commandLog records Redis commands sent by the confidential backend.
type commandLog struct {
	mu        sync.Mutex
	cmds      []string
	blockScan bool
	entered   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func newCommandLog(mr *miniredis.Miniredis) *commandLog {
	log := &commandLog{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	mr.Server().SetPreHook(func(_ *server.Peer, cmd string, _ ...string) bool {
		upper := strings.ToUpper(cmd)
		log.mu.Lock()
		log.cmds = append(log.cmds, upper)
		block := log.blockScan && (upper == "KEYS" || upper == "SCAN")
		log.mu.Unlock()
		if block {
			log.once.Do(func() { close(log.entered) })
			<-log.release
		}
		return false
	})
	return log
}

func (l *commandLog) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.cmds)
}

func (l *commandLog) since(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.cmds)-n)
	copy(out, l.cmds[n:])
	return out
}

type redisFixture struct {
	mr       *miniredis.Miniredis
	store    *RedisStoreBackend
	commands *commandLog
	attacker suave.Bid
	victim   suave.Bid
	caller   common.Address
	secret   string
}

func newRedisFixture(t *testing.T) *redisFixture {
	t.Helper()
	mr := miniredis.RunT(t)
	commands := newCommandLog(mr)

	store, err := NewRedisStoreBackend(mr.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Stop() })

	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	attacker := suave.Bid{
		Id:                  mustBidID("attacker-bid-id!"),
		DecryptionCondition: 10,
		AllowedPeekers:      []common.Address{caller},
		Version:             "default:v0:ethBundles",
	}
	victim := suave.Bid{
		Id:                  mustBidID("victim-bid-id!!!"),
		DecryptionCondition: 10,
		AllowedPeekers:      []common.Address{common.HexToAddress("0x2222222222222222222222222222222222222222")},
		Version:             "default:v0:ethBundles",
	}
	secret := "VICTIM-PAYLOAD-VALUE-9f3a"
	require.NoError(t, store.InitializeBid(attacker))
	require.NoError(t, store.InitializeBid(victim))
	_, err = store.Store(attacker, caller, "attacker-owned-key", []byte("attacker-value"))
	require.NoError(t, err)
	_, err = store.Store(victim, victim.AllowedPeekers[0], "victim-secret-name", []byte(secret))
	require.NoError(t, err)

	return &redisFixture{
		mr:       mr,
		store:    store,
		commands: commands,
		attacker: attacker,
		victim:   victim,
		caller:   caller,
		secret:   secret,
	}
}

func mustBidID(text string) suave.BidId {
	if len(text) != 16 {
		panic("bid id text must be 16 bytes")
	}
	var id suave.BidId
	copy(id[:], text)
	return id
}

func discloseText(err error) string {
	if err == nil {
		return ""
	}
	raw := err.Error()
	text := raw
	if i := strings.LastIndex(raw, "0x"); i >= 0 {
		if decoded, decErr := hexutil.Decode(raw[i:]); decErr == nil {
			text += "\n" + string(decoded)
		}
	}
	return text
}

func assertNoKeyspaceLeak(t *testing.T, err error, stored []string, cmds []string, secret string, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("missing confidential read returned success")
	}
	text := discloseText(err)
	for _, key := range append(append([]string{}, stored...), forbidden...) {
		if key != "" && strings.Contains(text, key) {
			t.Fatalf("missing read disclosed %q\nerror: %s", key, text)
		}
	}
	if secret != "" && strings.Contains(text, secret) {
		t.Fatalf("missing read disclosed stored value %q\nerror: %s", secret, text)
	}
	if scans := countScans(cmds); scans != 0 {
		t.Fatalf("missing read scanned the keyspace with %d KEYS/SCAN command(s): %v\nerror: %s", scans, cmds, text)
	}
	if countCmd(cmds, "GET") == 0 {
		t.Fatalf("missing read never queried redis, so it did not exercise Retrieve: %v\nerror: %s", cmds, text)
	}
}

func TestRedisMissingRetrieveDoesNotDiscloseOtherBids(t *testing.T) {
	fx := newRedisFixture(t)

	mark := fx.commands.len()
	_, err := fx.store.Retrieve(fx.attacker, fx.caller, "missing-key")
	first := fx.commands.since(mark)
	assertNoKeyspaceLeak(t, err, fx.mr.Keys(), first, fx.secret,
		formatRedisBidValueKey(fx.attacker.Id, "missing-key"),
		bidHex(fx.victim.Id),
		"victim-secret-name",
	)

	mark = fx.commands.len()
	_, err = fx.store.Retrieve(fx.attacker, fx.caller, "missing-key")
	second := fx.commands.since(mark)
	assertNoKeyspaceLeak(t, err, fx.mr.Keys(), second, fx.secret,
		formatRedisBidValueKey(fx.attacker.Id, "missing-key"),
		bidHex(fx.victim.Id),
		"victim-secret-name",
	)
}

func TestRedisMissErrorDoesNotDependOnOtherKeys(t *testing.T) {
	left := missError(t, "alpha-only-secret")
	right := missError(t, "beta-only-secret")
	if left != right {
		t.Fatalf("not-found error changes with the rest of the keyspace\n left: %s\nright: %s", left, right)
	}
	for _, secret := range []string{"alpha-only-secret", "beta-only-secret"} {
		if strings.Contains(left, secret) {
			t.Fatalf("not-found error contains other key material %q: %s", secret, left)
		}
	}
}

func TestRedisAuthorizedEngineRetrieveDoesNotDiscloseOtherBids(t *testing.T) {
	fx := newRedisFixture(t)
	engine := NewConfidentialStoreEngine(fx.store, MockTransport{}, MockSigner{}, MockChainSigner{})
	tx := types.NewTx(&types.ConfidentialComputeRequest{
		ConfidentialComputeRecord: types.ConfidentialComputeRecord{ExecutionNode: common.Address{0x42}},
	})
	store := engine.NewTransactionalStore(tx)

	mark := fx.commands.len()
	_, err := store.Retrieve(fx.attacker.Id, fx.caller, "missing-key")
	assertNoKeyspaceLeak(t, err, fx.mr.Keys(), fx.commands.since(mark), fx.secret,
		formatRedisBidValueKey(fx.attacker.Id, "missing-key"),
		bidHex(fx.victim.Id),
		"victim-secret-name",
	)

	// Authorization is checked before the backend read. A refused caller must
	// not scan the store or observe a bid they were not allowed to read.
	mark = fx.commands.len()
	_, denied := store.Retrieve(fx.attacker.Id, fx.victim.AllowedPeekers[0], "missing-key")
	if denied == nil {
		t.Fatal("unauthorized retrieve succeeded")
	}
	if scans := countScans(fx.commands.since(mark)); scans != 0 {
		t.Fatalf("unauthorized retrieve scanned the keyspace: %v", fx.commands.since(mark))
	}
	deniedText := discloseText(denied)
	if strings.Contains(deniedText, "victim-secret-name") || strings.Contains(deniedText, fx.secret) {
		t.Fatalf("unauthorized retrieve disclosed stored data: %s", deniedText)
	}
}

func TestRedisIndexAndFetchDoNotScanKeyspace(t *testing.T) {
	fx := newRedisFixture(t)

	t.Run("initialize", func(t *testing.T) {
		mark := fx.commands.len()
		extra := fx.attacker
		extra.Id = mustBidID("third-bid-id!!!!")
		// A new protocol/block has no index row yet, so indexing this bid reads a missing key.
		extra.Version = "fresh-namespace"
		extra.DecryptionCondition = 77
		require.NoError(t, fx.store.InitializeBid(extra))
		if scans := countScans(fx.commands.since(mark)); scans != 0 {
			t.Fatalf("InitializeBid scanned the keyspace: %v", fx.commands.since(mark))
		}
	})

	t.Run("fetch", func(t *testing.T) {
		mark := fx.commands.len()
		_ = fx.store.FetchBidsByProtocolAndBlock(404, "namespace-with-no-index")
		cmds := fx.commands.since(mark)
		if scans := countScans(cmds); scans != 0 {
			t.Fatalf("FetchBidsByProtocolAndBlock scanned the keyspace: %v", cmds)
		}
		if countCmd(cmds, "GET") == 0 {
			t.Fatalf("fetch never queried redis: %v", cmds)
		}
	})
}

func TestRedisMissingRetrieveBlocksOnKeyspaceScan(t *testing.T) {
	fx := newRedisFixture(t)
	fx.commands.blockScan = true
	defer close(fx.commands.release)

	mark := fx.commands.len()
	done := make(chan error, 1)
	go func() {
		_, err := fx.store.Retrieve(fx.attacker, fx.caller, "missing-key")
		done <- err
	}()

	select {
	case err := <-done:
		assertNoKeyspaceLeak(t, err, fx.mr.Keys(), fx.commands.since(mark), fx.secret,
			formatRedisBidValueKey(fx.attacker.Id, "missing-key"),
			bidHex(fx.victim.Id),
		)
	case <-fx.commands.entered:
		select {
		case err := <-done:
			t.Fatalf("retrieve returned while the keyspace scan was still running: %v", err)
		case <-time.After(50 * time.Millisecond):
			t.Fatal("missing confidential read blocked on a keyspace scan")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the missing read")
	}
}

func missError(t *testing.T, extraKey string) string {
	t.Helper()
	mr := miniredis.RunT(t)
	store, err := NewRedisStoreBackend(mr.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Stop() })

	caller := common.HexToAddress("0x1111111111111111111111111111111111111111")
	bid := suave.Bid{
		Id:             mustBidID("same-attacker-id"),
		AllowedPeekers: []common.Address{caller},
		Version:        "default:v0:ethBundles",
	}
	other := suave.Bid{
		Id:             mustBidID("same-victim-id!!"),
		AllowedPeekers: []common.Address{common.HexToAddress("0x99")},
		Version:        "default:v0:ethBundles",
	}
	require.NoError(t, store.InitializeBid(bid))
	require.NoError(t, store.InitializeBid(other))
	_, err = store.Store(other, other.AllowedPeekers[0], extraKey, []byte("hidden-"+extraKey))
	require.NoError(t, err)

	_, got := store.Retrieve(bid, caller, "missing-key")
	require.Error(t, got)
	return got.Error()
}

func countScans(cmds []string) int {
	return countCmd(cmds, "KEYS") + countCmd(cmds, "SCAN")
}

func countCmd(cmds []string, want string) int {
	n := 0
	for _, cmd := range cmds {
		if cmd == want {
			n++
		}
	}
	return n
}

func bidHex(id suave.BidId) string {
	return strings.TrimPrefix(hexutil.Encode(id[:]), "0x")
}
