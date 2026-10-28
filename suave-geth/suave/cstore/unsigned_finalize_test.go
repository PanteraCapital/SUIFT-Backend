package cstore

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	suave "github.com/ethereum/go-ethereum/suave/core"
	"github.com/stretchr/testify/require"
)

// These tests are the spec for the unsigned-finalize bug. They fail while
// Finalize still commits bids and payloads before the source transaction
// signature is verified, and they pass once that commit is refused.

func TestFinalizeUnsignedTransactionDoesNotCommitBidOrPayload(t *testing.T) {
	exec := common.Address{0x42}
	payload := []byte("unsigned-payload")

	for _, backend := range newStoreBackends(t) {
		t.Run(backend.name, func(t *testing.T) {
			transport := &captureTransport{}
			engine := newTestEngine(backend.store, transport, exec)
			source := unsignedConfidentialRequest(exec, []byte("unsigned-source"))

			bid, writes := pendingBidAndWrite(t, engine, source, payload)
			err := engine.Finalize(source, map[suave.BidId]suave.Bid{bid.Id: bid}, writes)
			require.ErrorIs(t, err, suave.ErrUnsignedFinalize)

			assertBidAndPayloadAbsent(t, backend.store, bid, "k", payload)
			require.Empty(t, transport.msgs, "unsigned finalize published a store message")
			if backend.local != nil {
				require.Empty(t, backend.local.bids)
				require.Empty(t, backend.local.dataMap)
				require.Empty(t, backend.local.index)
			}
		})
	}
}

func TestFinalizeSignedTransactionStillCommitsBidAndPayload(t *testing.T) {
	exec := common.Address{0x42}
	payload := []byte("signed-payload")
	key := mustKey(t)
	transport := &captureTransport{published: make(chan struct{}, 1)}
	local := NewLocalConfidentialStore()
	engine := newTestEngine(local, transport, exec)
	source := signedConfidentialRequest(t, key, exec, []byte("signed-source"))

	bid, writes := pendingBidAndWrite(t, engine, source, payload)
	require.NoError(t, engine.Finalize(source, map[suave.BidId]suave.Bid{bid.Id: bid}, writes))

	stored, err := local.FetchBidById(bid.Id)
	require.NoError(t, err)
	require.Equal(t, bid.Id, stored.Id)
	got, err := local.Retrieve(bid, exec, "k")
	require.NoError(t, err)
	require.Equal(t, payload, got)

	select {
	case <-transport.published:
	case <-time.After(2 * time.Second):
		t.Fatal("signed finalize did not publish the store message")
	}
}

func TestFinalizeDoesNotCommitBidsCreatedByADifferentUnsignedTransaction(t *testing.T) {
	exec := common.Address{0x42}
	payload := []byte("swapped-payload")
	key := mustKey(t)
	local := NewLocalConfidentialStore()
	engine := newTestEngine(local, &captureTransport{}, exec)

	unsigned := unsignedConfidentialRequest(exec, []byte("unsigned-source"))
	signed := signedConfidentialRequest(t, key, exec, []byte("signed-source"))
	require.NotEqual(t, unsigned.Hash(), signed.Hash())

	bid, writes := pendingBidAndWrite(t, engine, unsigned, payload)
	require.Equal(t, unsigned.Hash(), bid.CreationTx.Hash())
	for _, write := range writes {
		require.Equal(t, unsigned.Hash(), write.Bid.CreationTx.Hash())
	}

	// The transaction presented to Finalize is signed, but every pending bid
	// and store write was created by the unsigned transaction. Authorizing
	// the signed transaction must not commit those records.
	err := engine.Finalize(signed, map[suave.BidId]suave.Bid{bid.Id: bid}, writes)
	require.Error(t, err)
	assertBidAndPayloadAbsent(t, local, bid, "k", payload)
	require.Empty(t, local.bids)
	require.Empty(t, local.dataMap)
	require.Empty(t, local.index)
}

type namedBackend struct {
	name  string
	store ConfidentialStorageBackend
	local *LocalConfidentialStore
}

func newStoreBackends(t *testing.T) []namedBackend {
	t.Helper()
	local := NewLocalConfidentialStore()
	redisStore, err := NewRedisStoreBackend("")
	require.NoError(t, err)
	t.Cleanup(func() { _ = redisStore.Stop() })
	pebbleStore, err := NewPebbleStoreBackend(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = pebbleStore.Stop() })
	return []namedBackend{
		{name: "local", store: local, local: local},
		{name: "redis", store: redisStore},
		{name: "pebble", store: pebbleStore},
	}
}

func newTestEngine(store ConfidentialStorageBackend, transport StoreTransportTopic, exec common.Address) *ConfidentialStoreEngine {
	return NewConfidentialStoreEngine(store, transport, FakeDASigner{localAddresses: []common.Address{exec}}, MockChainSigner{})
}

func pendingBidAndWrite(t *testing.T, engine *ConfidentialStoreEngine, source *types.Transaction, payload []byte) (suave.Bid, []StoreWrite) {
	t.Helper()
	session := engine.NewTransactionalStore(source)
	inner, err := session.InitializeBid(types.Bid{
		Salt:                types.BidId{0x11},
		DecryptionCondition: 9,
		AllowedPeekers:      []common.Address{suave.AllowedPeekerAny},
		Version:             "unsigned-finalize",
	})
	require.NoError(t, err)
	bid, err := session.FetchBidById(inner.Id)
	require.NoError(t, err)
	_, err = session.Store(bid.Id, common.Address{0x42}, "k", payload)
	require.NoError(t, err)
	session.pendingLock.Lock()
	defer session.pendingLock.Unlock()
	return bid, append([]StoreWrite(nil), session.pendingWrites...)
}

func assertBidAndPayloadAbsent(t *testing.T, store ConfidentialStorageBackend, bid suave.Bid, key string, payload []byte) {
	t.Helper()
	_, err := store.FetchBidById(bid.Id)
	require.Error(t, err, "unsigned finalize left bid %x in the confidential store", bid.Id)
	for _, caller := range []common.Address{{0x42}, suave.AllowedPeekerAny, {}} {
		got, retrieveErr := store.Retrieve(bid, caller, key)
		require.Falsef(t, retrieveErr == nil && string(got) == string(payload), "unsigned finalize left payload under caller %x", caller)
	}
	require.Empty(t, store.FetchBidsByProtocolAndBlock(bid.DecryptionCondition, bid.Version))
}

func unsignedConfidentialRequest(exec common.Address, data []byte) *types.Transaction {
	return types.NewTx(&types.ConfidentialComputeRequest{
		ConfidentialComputeRecord: types.ConfidentialComputeRecord{
			ExecutionNode: exec,
			ChainID:       big.NewInt(1337),
			Nonce:         1,
			Gas:           1_000_000,
			GasPrice:      big.NewInt(1),
			Value:         big.NewInt(0),
			Data:          data,
		},
	})
}

func signedConfidentialRequest(t *testing.T, key *ecdsa.PrivateKey, exec common.Address, data []byte) *types.Transaction {
	t.Helper()
	chainID := big.NewInt(1337)
	tx, err := types.SignTx(types.NewTx(&types.ConfidentialComputeRequest{
		ConfidentialComputeRecord: types.ConfidentialComputeRecord{
			ExecutionNode: exec,
			ChainID:       chainID,
			Nonce:         1,
			Gas:           1_000_000,
			GasPrice:      big.NewInt(1),
			Value:         big.NewInt(0),
			Data:          data,
		},
	}), types.NewSuaveSigner(chainID), key)
	require.NoError(t, err)
	return tx
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	return key
}

type captureTransport struct {
	msgs      []DAMessage
	published chan struct{}
}

func (c *captureTransport) Start() error { return nil }
func (c *captureTransport) Stop() error  { return nil }
func (c *captureTransport) Subscribe() (<-chan DAMessage, context.CancelFunc) {
	return nil, func() {}
}
func (c *captureTransport) Publish(msg DAMessage) {
	c.msgs = append(c.msgs, msg)
	if c.published != nil {
		select {
		case c.published <- struct{}{}:
		default:
		}
	}
}
