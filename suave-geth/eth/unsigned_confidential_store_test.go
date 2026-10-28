package eth_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"crypto/ecdsa"

	"github.com/alicebob/miniredis/v2"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/suave/artifacts"
	suave "github.com/ethereum/go-ethereum/suave/core"
	"github.com/ethereum/go-ethereum/suave/cstore"
	"github.com/stretchr/testify/require"
)

// TestUnsignedConfidentialCallDoesNotCommit drives the attack through the
// live confidential eth_call path: an unsigned isConfidential call, an
// unlocked kettle execution account, newBid, and confidentialStore on a
// wildcard-peeker bid. The same DoCall implementation backs eth_estimateGas
// and the GraphQL block call/estimateGas resolvers, so those entries are
// covered here as well.
//
// The test fails while Finalize commits before the source signature check
// and DoCall treats ErrUnsignedFinalize as success. It passes once an
// unsigned call leaves the confidential store unchanged.
func TestUnsignedConfidentialCallDoesNotCommit(t *testing.T) {
	original := []byte("victim-payload")
	replacement := []byte("overwritten-by-unsigned-call")
	victim := common.HexToAddress("0x1111111111111111111111111111111111111111")
	storeCaller := artifacts.SuaveMethods["confidentialStore"]

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) suave.Config
	}{
		{name: "local", setup: func(t *testing.T) suave.Config { return suave.Config{} }},
		{name: "redis", setup: func(t *testing.T) suave.Config {
			return suave.Config{RedisStoreUri: miniredis.RunT(t).Addr()}
		}},
		{name: "pebble", setup: func(t *testing.T) suave.Config {
			return suave.Config{PebbleDbPath: t.TempDir()}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, client := startKettle(t, tc.setup(t))
			backend := srv.APIBackend.SuaveEngine().Backend()
			kettle := srv.AccountManager().Accounts()[0]

			t.Run("confidentialStore", func(t *testing.T) {
				bidID := suave.RandomBidId()
				bid := suave.Bid{
					Id:                  bidID,
					Salt:                suave.RandomBidId(),
					DecryptionCondition: 1,
					AllowedPeekers:      []common.Address{suave.AllowedPeekerAny},
					Version:             "wildcard",
				}
				require.NoError(t, backend.InitializeBid(bid))
				_, err := backend.Store(bid, victim, "payload", original)
				require.NoError(t, err)

				storeInput, err := artifacts.SuaveAbi.Methods["confidentialStore"].Inputs.Pack(bidID, "payload", replacement)
				require.NoError(t, err)
				var storeResult hexutil.Bytes
				storeErr := client.Call(&storeResult, "eth_call", confidentialCallArgs(t, "confidentialStore", storeInput), "latest")

				got, retrieveErr := backend.Retrieve(bid, victim, "payload")
				require.NoError(t, retrieveErr)
				require.Equalf(t, original, got, "unsigned eth_call overwrote a wildcard-peeker payload (rpc err=%v)", storeErr)
				attackerView, attackerErr := backend.Retrieve(bid, storeCaller, "payload")
				require.Falsef(t, attackerErr == nil && string(attackerView) == string(replacement), "unsigned eth_call stored %q for the precompile caller %s", replacement, storeCaller.Hex())
			})

			t.Run("newBid", func(t *testing.T) {
				assertUnsignedCallLeavesNoBid(t, client, srv, backend, "eth_call", 11, "unsigned:eth_call")
			})
			t.Run("estimateGas", func(t *testing.T) {
				assertUnsignedCallLeavesNoBid(t, client, srv, backend, "eth_estimateGas", 12, "unsigned:estimate")
			})
			t.Run("doCall", func(t *testing.T) {
				assertDirectDoCallLeavesNoBid(t, srv, backend, 13, "unsigned:docall")
			})
			if tc.name == "local" {
				t.Run("signed", func(t *testing.T) {
					assertSignedNewBidStillCommits(t, client, backend, kettle)
				})
			}
		})
	}
}

func assertUnsignedCallLeavesNoBid(t *testing.T, client *rpc.Client, srv *eth.Ethereum, backend cstore.ConfidentialStorageBackend, method string, block uint64, namespace string) {
	t.Helper()
	input := packNewBid(t, block, namespace)
	args := confidentialCallArgs(t, "newBid", input)
	var rpcErr error
	switch method {
	case "eth_call":
		var result hexutil.Bytes
		rpcErr = client.Call(&result, "eth_call", args, "latest")
	case "eth_estimateGas":
		var gas hexutil.Uint64
		rpcErr = client.Call(&gas, "eth_estimateGas", args, "latest")
	default:
		t.Fatalf("unknown method %s", method)
	}
	requireNoCommittedBid(t, backend, block, namespace, method, rpcErr)
}

func assertDirectDoCallLeavesNoBid(t *testing.T, srv *eth.Ethereum, backend cstore.ConfidentialStorageBackend, block uint64, namespace string) {
	t.Helper()
	args := confidentialCallArgs(t, "newBid", packNewBid(t, block, namespace))
	_, err := ethapi.DoCall(context.Background(), srv.APIBackend, args, rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber), nil, nil, 5*time.Second, srv.APIBackend.RPCGasCap())
	requireNoCommittedBid(t, backend, block, namespace, "ethapi.DoCall", err)
}

func assertSignedNewBidStillCommits(t *testing.T, client *rpc.Client, backend cstore.ConfidentialStorageBackend, kettle common.Address) {
	t.Helper()
	const block = uint64(21)
	const namespace = "signed:control"
	input := packNewBid(t, block, namespace)
	to := artifacts.SuaveMethods["newBid"]
	key := testUserKey(t)
	chainID := big.NewInt(1337)
	tx, err := types.SignTx(types.NewTx(&types.ConfidentialComputeRequest{
		ConfidentialComputeRecord: types.ConfidentialComputeRecord{
			ExecutionNode: kettle,
			ChainID:       chainID,
			To:            &to,
			Nonce:         0,
			Gas:           1_000_000,
			GasPrice:      big.NewInt(1),
			Value:         big.NewInt(0),
			Data:          input,
		},
	}), types.NewSuaveSigner(chainID), key)
	require.NoError(t, err)
	raw, err := tx.MarshalBinary()
	require.NoError(t, err)
	var hash common.Hash
	sendErr := client.Call(&hash, "eth_sendRawTransaction", hexutil.Bytes(raw))

	bids := backend.FetchBidsByProtocolAndBlock(block, namespace)
	require.Lenf(t, bids, 1, "signed confidential newBid did not commit (send err=%v)", sendErr)
	bidBytes, err := cstore.SerializeBidForSigning(&bids[0])
	require.NoError(t, err)
	recovered, err := crypto.SigToPub(crypto.Keccak256(bidBytes), bids[0].Signature)
	require.NoError(t, err)
	require.Equal(t, kettle, crypto.PubkeyToAddress(*recovered), "committed bid was not signed by the unlocked execution account")
}

func requireNoCommittedBid(t *testing.T, backend cstore.ConfidentialStorageBackend, block uint64, namespace string, op string, rpcErr error) {
	t.Helper()
	bids := backend.FetchBidsByProtocolAndBlock(block, namespace)
	if len(bids) != 0 {
		t.Fatalf("%s committed %d bid(s) from an unsigned confidential request (rpc err=%v); first id %x signature %x", op, len(bids), rpcErr, bids[0].Id, bids[0].Signature)
	}
}

func packNewBid(t *testing.T, block uint64, namespace string) []byte {
	t.Helper()
	input, err := artifacts.SuaveAbi.Methods["newBid"].Inputs.Pack(block, []common.Address{suave.AllowedPeekerAny}, []common.Address{}, namespace)
	require.NoError(t, err)
	return input
}

func confidentialCallArgs(t *testing.T, method string, input []byte) ethapi.TransactionArgs {
	t.Helper()
	to, ok := artifacts.SuaveMethods[method]
	require.True(t, ok)
	gas := hexutil.Uint64(1_000_000)
	nonce := hexutil.Uint64(0)
	gasPrice := hexutil.Big(*big.NewInt(0))
	value := hexutil.Big(*big.NewInt(0))
	chainID := hexutil.Big(*big.NewInt(1337))
	data := hexutil.Bytes(input)
	return ethapi.TransactionArgs{
		To:             &to,
		IsConfidential: true,
		ChainID:        &chainID,
		Data:           &data,
		Gas:            &gas,
		Nonce:          &nonce,
		GasPrice:       &gasPrice,
		Value:          &value,
	}
}

func startKettle(t *testing.T, suaveCfg suave.Config) (*eth.Ethereum, *rpc.Client) {
	t.Helper()
	genesisCfg := *params.AllEthashProtocolChanges
	genesisCfg.TerminalTotalDifficulty = new(big.Int)
	funded := crypto.PubkeyToAddress(testUserKey(t).PublicKey)
	genesis := &core.Genesis{
		Config:     &genesisCfg,
		Timestamp:  1680000000,
		GasLimit:   30_000_000,
		BaseFee:    big.NewInt(0),
		Difficulty: big.NewInt(0),
		Alloc: core.GenesisAlloc{
			funded: {Balance: big.NewInt(2e18)},
		},
	}

	stack, err := node.New(&node.Config{
		DataDir: t.TempDir(),
		P2P: p2p.Config{
			ListenAddr:  "127.0.0.1:0",
			NoDiscovery: true,
			MaxPeers:    0,
		},
	})
	require.NoError(t, err)
	srv, err := eth.New(stack, &ethconfig.Config{
		Genesis:        genesis,
		SyncMode:       downloader.FullSync,
		TrieTimeout:    time.Minute,
		TrieDirtyCache: 256,
		TrieCleanCache: 256,
		Suave:          suaveCfg,
	})
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	t.Cleanup(func() { stack.Close() })
	srv.SetSynced()

	ks := keystore.NewPlaintextKeyStore(t.TempDir())
	acc, err := ks.NewAccount("")
	require.NoError(t, err)
	require.NoError(t, ks.TimedUnlock(acc, "", time.Hour))
	srv.AccountManager().AddBackend(ks)
	require.NotEmpty(t, srv.AccountManager().Accounts())

	client, err := stack.Attach()
	require.NoError(t, err)
	t.Cleanup(client.Close)
	return srv, client
}

func testUserKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	require.NoError(t, err)
	return key
}
