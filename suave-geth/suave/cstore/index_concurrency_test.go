package cstore

import (
	"encoding/binary"
	"math/big"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	suave "github.com/ethereum/go-ethereum/suave/core"
	"github.com/stretchr/testify/require"
)

// These tests are expected to fail until the per-block bid index is updated
// atomically. RedisStoreBackend.indexBid and PebbleStoreBackend.InitializeBid
// both read the index, append one bid id, and write the list back. Confidential
// requests finalize on separate RPC goroutines, so overlapping updates drop ids.
// Block building reads bids only through FetchBidsByProtocolAndBlock.

const (
	indexRaceNamespace = "default:v0:ethBundles"
	indexRaceBlock     = uint64(42)
	indexRaceParallel  = 32
	indexRaceRounds    = 6
	indexRaceSeed      = 48
)

func TestConcurrentFinalizeRetainsEveryBidInFetchBids(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	creationTx := signedConfidentialRequest(t)

	t.Run("redis", func(t *testing.T) {
		backend, err := NewRedisStoreBackend("")
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Stop() })

		engine := NewConfidentialStoreEngine(backend, MockTransport{}, MockSigner{}, MockChainSigner{})
		assertConcurrentIndexRetainsBids(t, func(bid suave.Bid) error {
			return engine.Finalize(creationTx, map[suave.BidId]suave.Bid{bid.Id: bid}, nil)
		}, engine.FetchBidsByProtocolAndBlock, backend.FetchBidById)
	})

	t.Run("pebble", func(t *testing.T) {
		backend, err := NewPebbleStoreBackend(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Stop() })

		engine := NewConfidentialStoreEngine(backend, MockTransport{}, MockSigner{}, MockChainSigner{})
		assertConcurrentIndexRetainsBids(t, func(bid suave.Bid) error {
			return engine.Finalize(creationTx, map[suave.BidId]suave.Bid{bid.Id: bid}, nil)
		}, engine.FetchBidsByProtocolAndBlock, backend.FetchBidById)
	})
}

// TestConcurrentInitializeBidRetainsEveryBidInFetchBids covers the same index
// update when it is reached from storage.InitializeBid directly. Finalize and
// NewMessage both call that method, and neither holds a lock around it.
func TestConcurrentInitializeBidRetainsEveryBidInFetchBids(t *testing.T) {
	log.Root().SetHandler(log.DiscardHandler())
	t.Run("redis", func(t *testing.T) {
		backend, err := NewRedisStoreBackend("")
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Stop() })
		assertConcurrentIndexRetainsBids(t, backend.InitializeBid, backend.FetchBidsByProtocolAndBlock, backend.FetchBidById)
	})

	t.Run("pebble", func(t *testing.T) {
		backend, err := NewPebbleStoreBackend(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Stop() })
		assertConcurrentIndexRetainsBids(t, backend.InitializeBid, backend.FetchBidsByProtocolAndBlock, backend.FetchBidById)
	})
}

func assertConcurrentIndexRetainsBids(
	t *testing.T,
	submit func(suave.Bid) error,
	fetch func(uint64, string) []suave.Bid,
	fetchByID func(suave.BidId) (suave.Bid, error),
) {
	t.Helper()

	// Sequential inserts must be visible. A later miss is then an index loss,
	// not a backend that cannot store bids at all.
	for i := 0; i < indexRaceSeed; i++ {
		bid := raceBid(0, i)
		require.NoError(t, submit(bid))
	}
	requireIndexed(t, fetch, fetchByID, raceIDs(0, indexRaceSeed))

	for round := 1; round <= indexRaceRounds; round++ {
		ids := raceIDs(round, indexRaceParallel)
		errs := make([]error, len(ids))
		var ready sync.WaitGroup
		var goOn sync.WaitGroup
		start := make(chan struct{})
		ready.Add(len(ids))
		goOn.Add(len(ids))
		for i, id := range ids {
			i, id := i, id
			go func() {
				defer goOn.Done()
				ready.Done()
				<-start
				errs[i] = submit(raceBid(round, indexFromID(id)))
			}()
		}
		ready.Wait()
		close(start)
		goOn.Wait()

		for i, err := range errs {
			require.NoErrorf(t, err, "round %d bid %x failed to finalize", round, ids[i])
		}
		requireIndexed(t, fetch, fetchByID, ids)
	}
}

func requireIndexed(
	t *testing.T,
	fetch func(uint64, string) []suave.Bid,
	fetchByID func(suave.BidId) (suave.Bid, error),
	ids []suave.BidId,
) {
	t.Helper()

	fetched := fetch(indexRaceBlock, indexRaceNamespace)
	seen := make(map[suave.BidId]struct{}, len(fetched))
	for _, bid := range fetched {
		seen[bid.Id] = struct{}{}
	}

	var missing []suave.BidId
	for _, id := range ids {
		if _, ok := seen[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return
	}

	stillStored := 0
	for _, id := range missing {
		if _, err := fetchByID(id); err == nil {
			stillStored++
		}
	}
	t.Fatalf("fetchBids omitted %d/%d bid ids (%d of the omitted ids are still stored by id). index has %d bids. first missing id %x",
		len(missing), len(ids), stillStored, len(fetched), missing[0])
}

func raceIDs(round, n int) []suave.BidId {
	ids := make([]suave.BidId, n)
	for i := 0; i < n; i++ {
		var id suave.BidId
		binary.BigEndian.PutUint32(id[0:4], uint32(round))
		binary.BigEndian.PutUint32(id[4:8], uint32(i+1))
		ids[i] = id
	}
	return ids
}

func indexFromID(id suave.BidId) int {
	return int(binary.BigEndian.Uint32(id[4:8])) - 1
}

func raceBid(round, i int) suave.Bid {
	return suave.Bid{
		Id:                  raceIDs(round, i+1)[i],
		DecryptionCondition: indexRaceBlock,
		AllowedPeekers:      []common.Address{common.HexToAddress("0x424344")},
		Version:             indexRaceNamespace,
	}
}

func signedConfidentialRequest(t *testing.T) *types.Transaction {
	t.Helper()
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	tx, err := types.SignTx(types.NewTx(&types.ConfidentialComputeRequest{
		ConfidentialComputeRecord: types.ConfidentialComputeRecord{
			ExecutionNode: common.Address{},
		},
	}), types.NewSuaveSigner(new(big.Int)), key)
	require.NoError(t, err)
	return tx
}
