package e2e

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/suave/sdk"
	"github.com/stretchr/testify/require"
)

// These tests are the spec for the standard block builder.
//
// A bid stored in a builder namespace is allowed to omit the builder contract
// from its allowed-peeker list. fetchBids still returns that bid, and
// buildFromPool / buildMevShare call confidentialRetrieve on every returned
// bid. confidentialRetrieve reverts when the builder is not an allowed peeker,
// and that revert currently aborts the whole build, so an honest bid in the
// same namespace is never included.
//
// The build must still succeed, the honest transaction must be in the payload,
// and the restricted bid's transaction must not. Checking peekers and then
// still handing the restricted bid id to buildEthBlock does not satisfy this:
// buildEthBlock refuses that id and reverts the build. EthBlockBidSenderContract
// does not override buildFromPool or buildMevShare, so those calls run the
// same bodies. Auction.sol is not a builder entrypoint and is not covered.

const (
	ethBundlesNamespace = "default:v0:ethBundles"
	unmatchedNamespace  = "mevshare:v0:unmatchedBundles"
	matchBidsNamespace  = "mevshare:v0:matchBids"
	restrictedBidBlock  = uint64(2)
)

func TestRestrictedEthBundleDoesNotHaltBuildFromPool(t *testing.T) {
	fr := newFramework(t, WithExecutionNode())
	defer fr.Close()

	clt := fr.NewSDKClient()
	honestTx := signValueTransfer(t, clt, big.NewInt(1000))
	attackerTx := signValueTransfer(t, sdk.NewClient(fr.suethSrv.RPCNode(), testKey2, fr.ExecutionNode()), big.NewInt(1001))

	bundleBid := sdk.GetContract(newBundleBidAddress, BundleBidContract.Abi, clt)
	submitPoolBid(t, fr, bundleBid, "newBid", restrictedBidBlock, []common.Address{
		newBundleBidAddress,
		newBlockBidAddress,
		buildEthBlockAddress,
	}, honestTx)
	// The builder contract is omitted. The bundle contract must stay so the
	// bid can be stored, and the block-building precompile is included so a
	// check that only looks for that precompile still leaves the bid visible.
	submitPoolBid(t, fr, bundleBid, "newBid", restrictedBidBlock, []common.Address{
		newBundleBidAddress,
		buildEthBlockAddress,
	}, attackerTx)

	requireBidVisibleToPool(t, fr, ethBundlesNamespace, newBlockBidAddress)

	builder := sdk.GetContract(newBlockBidAddress, buildEthBlockContract.Abi, clt)
	payload := buildAndPayload(t, fr, builder, "buildFromPool", restrictedBidBlock)
	requirePayloadTxs(t, payload, honestTx, attackerTx)
}

func TestRestrictedUnmatchedBidDoesNotHaltBuildMevShare(t *testing.T) {
	fr := newFramework(t, WithExecutionNode())
	defer fr.Close()

	clt := fr.NewSDKClient()
	honestTx := signValueTransfer(t, clt, big.NewInt(1000))
	attackerTx := signValueTransfer(t, sdk.NewClient(fr.suethSrv.RPCNode(), testKey2, fr.ExecutionNode()), big.NewInt(1001))

	mevShare := sdk.GetContract(mevShareAddress, MevShareBidContract.Abi, clt)
	submitPoolBid(t, fr, mevShare, "newBid", restrictedBidBlock, []common.Address{
		mevShareAddress,
		newBlockBidAddress,
		buildEthBlockAddress,
	}, honestTx)
	submitPoolBid(t, fr, mevShare, "newBid", restrictedBidBlock, []common.Address{
		mevShareAddress,
		buildEthBlockAddress,
	}, attackerTx)

	requireBidVisibleToPool(t, fr, unmatchedNamespace, newBlockBidAddress)

	builder := sdk.GetContract(newBlockBidAddress, buildEthBlockContract.Abi, clt)
	payload := buildAndPayload(t, fr, builder, "buildMevShare", restrictedBidBlock)
	requirePayloadTxs(t, payload, honestTx, attackerTx)
}

func TestRestrictedMatchBidDoesNotHaltBuildMevShare(t *testing.T) {
	fr := newFramework(t, WithExecutionNode())
	defer fr.Close()

	clt := fr.NewSDKClient()
	honestTx := signValueTransfer(t, clt, big.NewInt(1000))
	attackerTx := signValueTransfer(t, sdk.NewClient(fr.suethSrv.RPCNode(), testKey2, fr.ExecutionNode()), big.NewInt(1001))

	mevShare := sdk.GetContract(mevShareAddress, MevShareBidContract.Abi, clt)
	honestBidId := submitPoolBid(t, fr, mevShare, "newBid", restrictedBidBlock, []common.Address{
		mevShareAddress,
		newBlockBidAddress,
		buildEthBlockAddress,
	}, honestTx)

	// newMatch indexes this bid under mevshare:v0:matchBids. buildMevShare
	// confidentialRetrieve's every match bid before it will use an honest
	// unmatched bundle, so one unreadable match bid aborts the build.
	_, err := mevShare.SendTransaction("newMatch", []interface{}{
		restrictedBidBlock,
		[]common.Address{mevShareAddress, buildEthBlockAddress},
		[]common.Address{fr.ExecutionNode()},
		honestBidId,
	}, confidentialBundle(t, attackerTx))
	requireNoRpcError(t, err)
	matchBlock := fr.suethSrv.ProgressChain()
	require.Equal(t, uint64(1), matchBlock.Receipts[0].Status)
	requireBidVisibleToPool(t, fr, matchBidsNamespace, newBlockBidAddress)

	builder := sdk.GetContract(newBlockBidAddress, buildEthBlockContract.Abi, clt)
	payload := buildAndPayload(t, fr, builder, "buildMevShare", restrictedBidBlock)
	requirePayloadTxs(t, payload, honestTx, attackerTx)
}

func signValueTransfer(t *testing.T, clt *sdk.Client, value *big.Int) *types.Transaction {
	t.Helper()
	tx, err := clt.SignTxn(&types.LegacyTx{
		Nonce:    0,
		To:       &testAddr,
		Value:    value,
		Gas:      21000,
		GasPrice: big.NewInt(13),
	})
	require.NoError(t, err)
	return tx
}

func confidentialBundle(t *testing.T, tx *types.Transaction) []byte {
	t.Helper()
	bundle := &types.SBundle{Txs: types.Transactions{tx}, RevertingHashes: []common.Hash{}}
	bundleBytes, err := json.Marshal(bundle)
	require.NoError(t, err)
	confidentialData, err := BundleBidContract.Abi.Methods["fetchBidConfidentialBundleData"].Outputs.Pack(bundleBytes)
	require.NoError(t, err)
	return confidentialData
}

func submitPoolBid(t *testing.T, fr *framework, contract *sdk.Contract, method string, block uint64, peekers []common.Address, tx *types.Transaction) types.BidId {
	t.Helper()
	_, err := contract.SendTransaction(method, []interface{}{
		block,
		peekers,
		[]common.Address{fr.ExecutionNode()},
	}, confidentialBundle(t, tx))
	requireNoRpcError(t, err)

	mined := fr.suethSrv.ProgressChain()
	require.Equal(t, uint64(1), mined.Receipts[0].Status)
	require.NotEmpty(t, mined.Receipts[0].Logs)

	unpacked, err := BundleBidContract.Abi.Events["BidEvent"].Inputs.Unpack(mined.Receipts[0].Logs[0].Data)
	require.NoError(t, err)
	return unpacked[0].([16]byte)
}

func requireBidVisibleToPool(t *testing.T, fr *framework, namespace string, builder common.Address) {
	t.Helper()
	bids := fr.ConfidentialEngine().FetchBidsByProtocolAndBlock(restrictedBidBlock, namespace)
	require.NotEmpty(t, bids)

	restricted := 0
	readable := 0
	for _, bid := range bids {
		if addressIn(bid.AllowedPeekers, builder) {
			readable++
		} else {
			restricted++
		}
	}
	require.Greater(t, restricted, 0, "restricted bid was not indexed in %s", namespace)
	if namespace != matchBidsNamespace {
		require.Greater(t, readable, 0, "honest bid was not indexed in %s", namespace)
	}
}

func buildAndPayload(t *testing.T, fr *framework, builder *sdk.Contract, method string, block uint64) *engine.ExecutionPayloadEnvelope {
	t.Helper()
	ethHead := fr.ethSrv.CurrentBlock()
	args := types.BuildBlockArgs{
		ProposerPubkey: []byte{0x42},
		Timestamp:      ethHead.Time + 12,
		FeeRecipient:   common.Address{0x42},
	}
	_, err := builder.SendTransaction(method, []interface{}{args, block}, nil)
	requireNoRpcError(t, err)

	mined := fr.suethSrv.ProgressChain()
	require.Equal(t, uint64(1), mined.Receipts[0].Status)
	require.GreaterOrEqual(t, len(mined.Receipts[0].Logs), 2)

	unpacked, err := BundleBidContract.Abi.Events["BidEvent"].Inputs.Unpack(mined.Receipts[0].Logs[1].Data)
	require.NoError(t, err)
	bidId := unpacked[0].([16]byte)

	payloadData, err := fr.ConfidentialEngine().Retrieve(bidId, newBlockBidAddress, "default:v0:builderPayload")
	require.NoError(t, err)

	var envelope engine.ExecutionPayloadEnvelope
	require.NoError(t, json.Unmarshal(payloadData, &envelope))
	require.NotNil(t, envelope.ExecutionPayload)
	return &envelope
}

func requirePayloadTxs(t *testing.T, envelope *engine.ExecutionPayloadEnvelope, want *types.Transaction, forbid *types.Transaction) {
	t.Helper()
	ethBlock, err := engine.ExecutableDataToBlock(*envelope.ExecutionPayload)
	require.NoError(t, err)

	foundWant := false
	for _, tx := range ethBlock.Transactions() {
		require.NotEqual(t, forbid.Hash(), tx.Hash(), "restricted bid was included in the built block")
		if tx.Hash() == want.Hash() {
			foundWant = true
		}
	}
	require.True(t, foundWant, "honest bid was not included in the built block")
}

func addressIn(list []common.Address, needle common.Address) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}
