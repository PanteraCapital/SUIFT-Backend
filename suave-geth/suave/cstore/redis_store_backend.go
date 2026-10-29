package cstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	suave "github.com/ethereum/go-ethereum/suave/core"
	"github.com/go-redis/redis/v8"
)

var _ ConfidentialStorageBackend = &RedisStoreBackend{}

var (
	formatRedisBidKey = func(bidId suave.BidId) string {
		return fmt.Sprintf("bid-%x", bidId)
	}

	formatRedisBidValueKey = func(bidId suave.BidId, key string) string {
		return fmt.Sprintf("bid-data-%x-%s", bidId, key)
	}

	formatRedisBidIndexKey = func(blockNumber uint64, namespace string) string {
		return fmt.Sprintf("bid-index-protocol-%s-bn-%d", namespace, blockNumber)
	}

	// Index written by earlier versions as a JSON list stored on the mempool bid.
	formatRedisLegacyBidIndexKey = func(blockNumber uint64, namespace string) string {
		return fmt.Sprintf("protocol-%s-bn-%d", namespace, blockNumber)
	}

	ffStoreTTL = 24 * time.Hour
)

type RedisStoreBackend struct {
	ctx      context.Context
	cancel   context.CancelFunc
	redisUri string
	client   *redis.Client
	local    *miniredis.Miniredis
}

func NewRedisStoreBackend(redisUri string) (*RedisStoreBackend, error) {
	r := &RedisStoreBackend{
		cancel:   nil,
		redisUri: redisUri,
	}

	if err := r.start(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RedisStoreBackend) start() error {
	if r.redisUri == "" {
		// create a mini-redis instance
		localRedis, err := miniredis.Run()
		if err != nil {
			return err
		}
		r.local = localRedis
		r.redisUri = localRedis.Addr()
	}

	if r.cancel != nil {
		r.cancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.ctx = ctx

	client, err := connectRedis(r.redisUri)
	if err != nil {
		return err
	}
	r.client = client

	err = r.InitializeBid(mempoolConfidentialStoreBid)
	if err != nil && !errors.Is(err, suave.ErrBidAlreadyPresent) {
		return fmt.Errorf("mempool: could not initialize: %w", err)
	}

	return nil
}

func (r *RedisStoreBackend) Stop() error {
	if r.cancel == nil || r.client == nil {
		return errors.New("Redis store: Stop() called before Start()")
	}

	if r.local != nil {
		r.local.Close()
	}
	r.cancel()
	r.client.Close()

	return nil
}

func (r *RedisStoreBackend) InitializeBid(bid suave.Bid) error {
	key := formatRedisBidKey(bid.Id)

	data, err := json.Marshal(bid)
	if err != nil {
		return err
	}

	created, err := r.client.SetNX(r.ctx, key, string(data), ffStoreTTL).Result()
	if err != nil {
		return err
	}
	if !created {
		return suave.ErrBidAlreadyPresent
	}

	err = r.indexBid(bid)
	if err != nil {
		return err
	}

	return nil
}

func (r *RedisStoreBackend) FetchBidById(bidId suave.BidId) (suave.Bid, error) {
	key := formatRedisBidKey(bidId)

	data, err := r.client.Get(r.ctx, key).Bytes()
	if err != nil {
		return suave.Bid{}, err
	}

	var bid suave.Bid
	err = json.Unmarshal(data, &bid)
	if err != nil {
		return suave.Bid{}, err
	}

	return bid, nil
}

func (r *RedisStoreBackend) Store(bid suave.Bid, caller common.Address, key string, value []byte) (suave.Bid, error) {
	storeKey := formatRedisBidValueKey(bid.Id, key)
	err := r.client.Set(r.ctx, storeKey, string(value), ffStoreTTL).Err()
	if err != nil {
		return suave.Bid{}, fmt.Errorf("unexpected redis error: %w", err)
	}

	return bid, nil
}

func (r *RedisStoreBackend) Retrieve(bid suave.Bid, caller common.Address, key string) ([]byte, error) {
	storeKey := formatRedisBidValueKey(bid.Id, key)
	data, err := r.client.Get(r.ctx, storeKey).Bytes()
	if err != nil {
		return []byte{}, fmt.Errorf("unexpected redis error: %w, %s, %v", err, storeKey, r.client.Keys(context.TODO(), "*").String())
	}

	return data, nil
}

var (
	mempoolConfStoreId          = types.BidId{0x39}
	mempoolConfStoreAddr        = common.HexToAddress("0x39")
	mempoolConfidentialStoreBid = suave.Bid{Id: mempoolConfStoreId, AllowedPeekers: []common.Address{mempoolConfStoreAddr}}
)

func (r *RedisStoreBackend) indexBid(bid suave.Bid) error {
	defer log.Info("bid submitted", "bid", bid, "store", r.Store)

	// The index is appended to server-side so that concurrent writers, including
	// other kettles sharing this Redis, cannot overwrite each other's entries.
	key := formatRedisBidIndexKey(bid.DecryptionCondition, bid.Version)
	_, err := r.client.TxPipelined(r.ctx, func(pipe redis.Pipeliner) error {
		pipe.RPush(r.ctx, key, bid.Id[:])
		pipe.Expire(r.ctx, key, ffStoreTTL)
		return nil
	})
	if err != nil {
		return fmt.Errorf("could not index bid %x: %w", bid.Id, err)
	}

	return nil
}

func (r *RedisStoreBackend) FetchBidsByProtocolAndBlock(blockNumber uint64, namespace string) []suave.Bid {
	var bidIDs []suave.BidId

	legacyIndexBytes, err := r.Retrieve(mempoolConfidentialStoreBid, mempoolConfStoreAddr, formatRedisLegacyBidIndexKey(blockNumber, namespace))
	if err == nil {
		var legacyIDs []suave.BidId
		if err := json.Unmarshal(legacyIndexBytes, &legacyIDs); err == nil {
			bidIDs = append(bidIDs, legacyIDs...)
		}
	}

	rawIDs, err := r.client.LRange(r.ctx, formatRedisBidIndexKey(blockNumber, namespace), 0, -1).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		log.Error("could not fetch bid index", "blockNumber", blockNumber, "namespace", namespace, "err", err)
	}
	for _, rawID := range rawIDs {
		var id suave.BidId
		if len(rawID) != len(id) {
			continue
		}
		copy(id[:], rawID)
		bidIDs = append(bidIDs, id)
	}

	if len(bidIDs) == 0 {
		return nil
	}

	res := []suave.Bid{}
	seen := make(map[suave.BidId]struct{}, len(bidIDs))
	for _, id := range bidIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}

		bid, err := r.FetchBidById(id)
		if err != nil {
			continue
		}
		res = append(res, bid)
	}

	// defer log.Info("bids fetched", "bids", string(bidsByProtocolBytes))
	return res
}
