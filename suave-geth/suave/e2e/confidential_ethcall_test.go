package e2e

import (
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/suave/artifacts"
	"github.com/stretchr/testify/require"
)

// These tests specify the behavior required to close the unsigned eth_call
// confidential-execution hole. They fail while DoCall still enters the MEVM
// for isConfidential, and they pass once an unsigned call cannot run a
// confidential precompile or return its output.
//
// The oracle is submitEthBlockBidToRelay, which performs an HTTP POST inside
// RunConfidential, before runMEVM asks the execution account to sign. A fix
// that still executes the precompile and only then rejects the call leaves
// the request count non-zero and fails these tests.

const relayLeakToken = "relay-body-20bd741f-698d-474d-a9e8-828a8ecb3dd1"

func TestEthCallIsConfidentialDoesNotRunPrecompileWithoutSignature(t *testing.T) {
	hits, srv := newRelayProbe(t, http.StatusInternalServerError)
	defer srv.Close()

	fr := newFramework(t)
	defer fr.Close()

	var result hexutil.Bytes
	err := fr.suethSrv.RPCNode().Call(&result, "eth_call", confidentialRelayCall(t, srv.URL, nil), "latest")
	t.Logf("eth_call omitted executionNode: result=%x err=%v", []byte(result), err)

	require.Zero(t, hits.Load(), "unsigned eth_call with isConfidential ran submitEthBlockBidToRelay before any refusal")
	require.NotContains(t, rpcErrText(err), relayLeakToken, "precompile error payload was returned to the eth_call caller")
	require.NotContains(t, strings.ToLower(string(result)), strings.ToLower(relayLeakToken))
}

func TestEthCallIsConfidentialExplicitLocalExecutionNodeDoesNotRunPrecompile(t *testing.T) {
	hits, srv := newRelayProbe(t, http.StatusInternalServerError)
	defer srv.Close()

	fr := newFramework(t)
	defer fr.Close()

	// A second local account, not whatever Accounts()[0] DoCall would default to.
	ks := keystore.NewPlaintextKeyStore(t.TempDir())
	acc, err := ks.NewAccount("")
	require.NoError(t, err)
	require.NoError(t, ks.TimedUnlock(acc, "", time.Hour))
	fr.suethSrv.service.AccountManager().AddBackend(ks)
	require.NotEqual(t, fr.ExecutionNode(), acc.Address)

	var result hexutil.Bytes
	err = fr.suethSrv.RPCNode().Call(&result, "eth_call", confidentialRelayCall(t, srv.URL, &acc.Address), "latest")
	t.Logf("eth_call explicit executionNode: result=%x err=%v", []byte(result), err)

	require.Zero(t, hits.Load(), "unsigned eth_call naming a local execution node ran the confidential precompile")
	require.NotContains(t, rpcErrText(err), relayLeakToken)
}

func TestEthCallIsConfidentialLockedExecutionNodeHasNoPrecompileSideEffect(t *testing.T) {
	// 204 makes RunConfidential succeed, so the only later refusal is SignTx on
	// the locked account. The POST must not happen before that refusal.
	hits, srv := newRelayProbe(t, http.StatusNoContent)
	defer srv.Close()

	fr := newFramework(t)
	defer fr.Close()

	ks := keystore.NewPlaintextKeyStore(t.TempDir())
	acc, err := ks.NewAccount("")
	require.NoError(t, err)
	fr.suethSrv.service.AccountManager().AddBackend(ks)

	var result hexutil.Bytes
	err = fr.suethSrv.RPCNode().Call(&result, "eth_call", confidentialRelayCall(t, srv.URL, &acc.Address), "latest")
	t.Logf("eth_call locked executionNode: result=%x err=%v", []byte(result), err)

	require.Zero(t, hits.Load(), "confidential precompile ran before the locked execution account was asked to sign")
	require.NotContains(t, string(result), relayLeakToken)
}

func TestEthCallIsConfidentialPrecompileErrorIsNotReturned(t *testing.T) {
	hits, srv := newRelayProbe(t, http.StatusInternalServerError)
	defer srv.Close()

	fr := newFramework(t)
	defer fr.Close()

	var result hexutil.Bytes
	err := fr.suethSrv.RPCNode().Call(&result, "eth_call", confidentialRelayCall(t, srv.URL, nil), "latest")
	t.Logf("eth_call precompile error: result=%x err=%v", []byte(result), err)

	require.Zero(t, hits.Load(), "precompile with a failing outbound request still executed")
	require.NotContains(t, rpcErrText(err), relayLeakToken, "precompile error payload was returned before the execution account was asked to sign")
	require.NotContains(t, string(result), relayLeakToken)
}

func TestEthEstimateGasIsConfidentialDoesNotRunPrecompile(t *testing.T) {
	hits, srv := newRelayProbe(t, http.StatusInternalServerError)
	defer srv.Close()

	fr := newFramework(t)
	defer fr.Close()

	var gas hexutil.Uint64
	err := fr.suethSrv.RPCNode().Call(&gas, "eth_estimateGas", confidentialRelayCall(t, srv.URL, nil))
	t.Logf("eth_estimateGas: gas=%d err=%v", gas, err)

	require.Zero(t, hits.Load(), "eth_estimateGas with isConfidential entered the MEVM through DoCall")
	require.NotContains(t, rpcErrText(err), relayLeakToken)
}

func TestEthCallIsConfidentialDoesNotReturnPrecompileOutput(t *testing.T) {
	fr := newFramework(t)
	defer fr.Close()

	ks := keystore.NewPlaintextKeyStore(t.TempDir())
	acc, err := ks.NewAccount("")
	require.NoError(t, err)
	require.NoError(t, ks.TimedUnlock(acc, "", time.Hour))
	fr.suethSrv.service.AccountManager().AddBackend(ks)

	secret := hexutil.Bytes("confidential-inputs-20bd741f")
	confidentialInputs := common.HexToAddress("0x42010001")

	cases := []struct {
		name string
		node *common.Address
	}{
		{name: "default execution node", node: nil},
		{name: "explicit unlocked execution node", node: &acc.Address},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var revealed hexutil.Bytes
			err := fr.suethSrv.RPCNode().Call(&revealed, "eth_call", setTxArgsDefaults(ethapi.TransactionArgs{
				To:                 &confidentialInputs,
				IsConfidential:     true,
				ExecutionNode:      tc.node,
				ConfidentialInputs: &secret,
			}), "latest")
			t.Logf("confidentialInputs: result=%q err=%v", []byte(revealed), err)
			require.NotContains(t, string(revealed), "confidential-inputs-20bd741f")
			require.NotContains(t, rpcErrText(err), "confidential-inputs-20bd741f")

			var flag hexutil.Bytes
			err = fr.suethSrv.RPCNode().Call(&flag, "eth_call", setTxArgsDefaults(ethapi.TransactionArgs{
				To:             &isConfidentialAddress,
				IsConfidential: true,
				ExecutionNode:  tc.node,
			}), "latest")
			t.Logf("isConfidential: result=%x err=%v", []byte(flag), err)
			// RunConfidential returns 0x01. The ordinary interpreter returns 0x00.
			if err == nil {
				require.NotEqual(t, []byte{0x01}, []byte(flag), "unsigned eth_call received the confidential precompile result")
			}
		})
	}
}

func TestUnsignedSendRawTransactionDoesNotRunPrecompile(t *testing.T) {
	// eth_sendRawTransaction shares runMEVM, but TransactionToMessage recovers
	// the sender before that. An unsigned confidential request must not reach
	// the precompile. This stays green on the current tree.
	hits, srv := newRelayProbe(t, http.StatusInternalServerError)
	defer srv.Close()

	fr := newFramework(t)
	defer fr.Close()

	executionNode := fr.ExecutionNode()
	args := confidentialRelayCall(t, srv.URL, &executionNode)
	tx := types.NewTx(&types.ConfidentialComputeRequest{
		ConfidentialComputeRecord: types.ConfidentialComputeRecord{
			ExecutionNode: fr.ExecutionNode(),
			Nonce:         0,
			To:            args.To,
			Value:         big.NewInt(0),
			Gas:           1_000_000,
			GasPrice:      big.NewInt(0),
			Data:          []byte(*args.Data),
		},
	})
	raw, err := tx.MarshalBinary()
	require.NoError(t, err)

	var hash common.Hash
	err = fr.suethSrv.RPCNode().Call(&hash, "eth_sendRawTransaction", hexutil.Encode(raw))
	t.Logf("eth_sendRawTransaction unsigned: hash=%s err=%v", hash, err)

	require.Error(t, err)
	require.Zero(t, hits.Load(), "unsigned eth_sendRawTransaction ran the confidential precompile")
	require.NotContains(t, rpcErrText(err), relayLeakToken)
}

func TestUnknownExecutionNodeIsRejectedBeforePrecompile(t *testing.T) {
	hits, srv := newRelayProbe(t, http.StatusInternalServerError)
	defer srv.Close()

	fr := newFramework(t)
	defer fr.Close()

	unknown := common.HexToAddress("0x1111111111111111111111111111111111111111")
	var result hexutil.Bytes
	err := fr.suethSrv.RPCNode().Call(&result, "eth_call", confidentialRelayCall(t, srv.URL, &unknown), "latest")
	t.Logf("unknown executionNode: result=%x err=%v", []byte(result), err)

	require.Error(t, err)
	require.Zero(t, hits.Load(), "precompile ran for an execution node that is not a local account")
	require.NotContains(t, rpcErrText(err), relayLeakToken)
}

func TestNonConfidentialEthCallDoesNotRunSuavePrecompile(t *testing.T) {
	hits, srv := newRelayProbe(t, http.StatusInternalServerError)
	defer srv.Close()

	fr := newFramework(t)
	defer fr.Close()

	args := confidentialRelayCall(t, srv.URL, nil)
	args.IsConfidential = false
	var result hexutil.Bytes
	err := fr.suethSrv.RPCNode().Call(&result, "eth_call", args, "latest")
	t.Logf("isConfidential false: result=%x err=%v", []byte(result), err)

	require.Zero(t, hits.Load())
	require.NotContains(t, rpcErrText(err), relayLeakToken)
}

func newRelayProbe(t *testing.T, status int) (*atomic.Int32, *httptest.Server) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		t.Logf("relay probe received %s %s body=%s", r.Method, r.URL.Path, body)
		w.WriteHeader(status)
		if status != http.StatusNoContent {
			_, _ = io.WriteString(w, relayLeakToken)
		}
	}))
	return &hits, srv
}

func confidentialRelayCall(t *testing.T, relayURL string, executionNode *common.Address) ethapi.TransactionArgs {
	t.Helper()
	method, ok := artifacts.SuaveAbi.Methods["submitEthBlockBidToRelay"]
	require.True(t, ok)
	packed, err := method.Inputs.Pack(relayURL, []byte(`{"probe":true}`))
	require.NoError(t, err)
	data := hexutil.Bytes(packed)
	return setTxArgsDefaults(ethapi.TransactionArgs{
		To:             &submitEthBlockBidToRelayAddress,
		IsConfidential: true,
		ExecutionNode:  executionNode,
		Data:           &data,
	})
}

func rpcErrText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// submitEthBlockBidToRelayAddress is the precompile that POSTs to a caller-chosen URL.
var submitEthBlockBidToRelayAddress = common.HexToAddress("0x42100002")
