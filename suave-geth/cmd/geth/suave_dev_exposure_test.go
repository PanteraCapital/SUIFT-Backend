// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rpc"
)

// publishedExecutionKeyHex is the execution-node private key checked into
// suave/devenv/README.md. Tests derive the address from it and require that
// this key cannot be recovered from the tree or from a dev-mode process.
const publishedExecutionKeyHex = "6c45335a22461ccdb978b78ab61b238bad2fae4544fb55c14eb096c875ccfc52"

// These tests describe the safe behavior of suave dev mode and the checked-in
// execution-node key. They fail while that key is embedded, encrypted with an
// empty password, unlocked, and reachable through a non-loopback RPC listener.

func TestPublishedExecutionKeystoreRejectsEmptyPassword(t *testing.T) {
	published := publishedExecutionAddress(t)
	root := repoRoot(t)

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			base := info.Name()
			if base == ".git" || base == "vendor" || base == "node_modules" || base == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > 5<<20 || skipGeneratedPath(path) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, publishedExecutionKeyHex) {
			offenders = append(offenders, rel+" contains the published execution private key")
		}
		if !bytes.Contains(data, []byte("ciphertext")) {
			return nil
		}
		for _, blob := range keystoreBlobs(data) {
			key, err := keystore.DecryptKey(blob, "")
			if err != nil {
				continue
			}
			if key.Address == published {
				offenders = append(offenders, rel+" decrypts with an empty password to "+key.Address.Hex())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, offender := range offenders {
		t.Error(offender)
	}
}

func TestSuaveDevModeDoesNotOfferRemoteSigning(t *testing.T) {
	if err := os.RemoveAll("/tmp/suave-dev"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll("/tmp/suave-dev") })
	requirePortsFree(t, 8545, 8546)

	geth := runGeth(t,
		"--suave.dev",
		"--authrpc.port", "0",
		"--cache", "64",
		"--datadir.minfreedisk", "0",
		"--nat", "none",
	)
	t.Cleanup(func() {
		geth.Kill()
		geth.WaitExit()
	})

	if !waitTCP("127.0.0.1:8546", 90*time.Second) {
		t.Fatalf("suave dev mode did not open the WebSocket listener\n%s", geth.StderrText())
	}
	assertNoRemoteSigning(t, 8545, 8546)
	assertDirectoryRejectsEmptyPassword(t, "/tmp/suave-dev")
}

func TestDevenvFlagsDoNotOfferRemoteSigning(t *testing.T) {
	root := repoRoot(t)
	keystoreDir := filepath.Join(root, "suave-geth", "suave", "devenv", "suave-ex-node", "keystore")
	passwordFile := filepath.Join(root, "suave-geth", "suave", "devenv", "suave-ex-node", "password.txt")
	requirePortsFree(t, 8545, 8546)

	// Same flags as suave/devenv/docker-compose.yml for the execution node.
	geth := runGeth(t,
		"--dev",
		"--dev.gaslimit", "30000000",
		"--http",
		"--http.port", "8545",
		"--http.addr", "0.0.0.0",
		"--http.vhosts", "*",
		"--http.corsdomain", "*",
		"--ws",
		"--ws.origins", "*",
		"--ws.addr", "0.0.0.0",
		"--keystore", keystoreDir,
		"--unlock", "0xB5fEAfbDD752ad52Afb7e1bD2E40432A485bBB7F",
		"--password", passwordFile,
		"--authrpc.port", "0",
		"--cache", "64",
		"--datadir.minfreedisk", "0",
		"--nat", "none",
	)
	t.Cleanup(func() {
		geth.Kill()
		geth.WaitExit()
	})

	if !waitTCP("127.0.0.1:8545", 90*time.Second) || !waitTCP("127.0.0.1:8546", 10*time.Second) {
		t.Fatalf("devenv flags did not open HTTP and WebSocket\n%s", geth.StderrText())
	}
	assertNoRemoteSigning(t, 8545, 8546)
}

func publishedExecutionAddress(t *testing.T) common.Address {
	t.Helper()
	key, err := crypto.HexToECDSA(publishedExecutionKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.PubkeyToAddress(key.PublicKey)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func skipGeneratedPath(path string) bool {
	base := filepath.Base(path)
	if base == "suave_dev_exposure_test.go" {
		return true
	}
	return strings.HasSuffix(base, "_test.go")
}

func assertDirectoryRejectsEmptyPassword(t *testing.T, dir string) {
	t.Helper()
	published := publishedExecutionAddress(t)
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	err = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || info.Size() > 1<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Contains(data, []byte("ciphertext")) {
			return nil
		}
		passwords := []string{""}
		if pw, err := os.ReadFile(filepath.Join(dir, "password.txt")); err == nil {
			passwords = append(passwords, string(pw))
		}
		for _, blob := range keystoreBlobs(data) {
			for _, password := range passwords {
				key, err := keystore.DecryptKey(blob, password)
				if err != nil {
					continue
				}
				if password == "" || key.Address == published {
					t.Errorf("%s decrypted with password %q to %s", path, password, key.Address.Hex())
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func keystoreBlobs(data []byte) [][]byte {
	var blobs [][]byte
	for idx := 0; idx < len(data); idx++ {
		if data[idx] != '{' {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(data[idx:]))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			continue
		}
		if bytes.Contains(raw, []byte(`"ciphertext"`)) && bytes.Contains(raw, []byte(`"kdf"`)) {
			blobs = append(blobs, append([]byte(nil), raw...))
			if len(raw) > 0 {
				idx += len(raw) - 1
			}
		}
	}
	return blobs
}

func requirePortsFree(t *testing.T, ports ...int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last error
	for {
		last = nil
		var lns []net.Listener
		for _, port := range ports {
			ln, err := net.Listen("tcp", "127.0.0.1:"+itoa(port))
			if err != nil {
				last = err
				for _, open := range lns {
					open.Close()
				}
				break
			}
			lns = append(lns, ln)
		}
		for _, ln := range lns {
			ln.Close()
		}
		if last == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ports %v are already in use: %v", ports, last)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func assertNoRemoteSigning(t *testing.T, ports ...int) {
	t.Helper()
	ips := nonLoopbackIPv4(t)
	for _, port := range ports {
		listeners := listeningAddrs(t, port)
		remote := false
		for _, ip := range listeners {
			if ip.IsUnspecified() || !ip.IsLoopback() {
				remote = true
			}
		}
		t.Logf("port %d listeners: %v remote=%v", port, listeners, remote)
		if !remote {
			continue
		}
		reached := false
		for _, ip := range ips {
			for _, scheme := range []string{"ws", "http"} {
				endpoint := scheme + "://" + ip + ":" + itoa(port)
				for _, origin := range []string{"", "https://attacker.example"} {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					client, err := dialRPC(ctx, endpoint, origin)
					cancel()
					if err != nil {
						t.Logf("dial %s origin %q: %v", endpoint, origin, err)
						continue
					}
					reached = true
					label := endpoint
					if origin != "" {
						label += " origin " + origin
					}
					exerciseRemoteSigning(t, client, label)
					client.Close()
				}
			}
		}
		if !reached {
			t.Errorf("port %d is listening on %v but no non-loopback RPC dial succeeded", port, listeners)
		}
	}
}

func dialRPC(ctx context.Context, endpoint, origin string) (*rpc.Client, error) {
	if origin == "" {
		return rpc.DialContext(ctx, endpoint)
	}
	if strings.HasPrefix(endpoint, "ws") {
		return rpc.DialWebsocket(ctx, endpoint, origin)
	}
	return rpc.DialOptions(ctx, endpoint, rpc.WithHeader("Origin", origin))
}

func exerciseRemoteSigning(t *testing.T, client *rpc.Client, endpoint string) {
	t.Helper()
	published := publishedExecutionAddress(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	addrs := []common.Address{published}
	var listed []common.Address
	if err := client.CallContext(ctx, &listed, "eth_accounts"); err != nil {
		t.Logf("%s eth_accounts: %v", endpoint, err)
	} else {
		addrs = append(addrs, listed...)
		t.Logf("%s eth_accounts: %v", endpoint, listed)
	}
	var exec []common.Address
	if err := client.CallContext(ctx, &exec, "eth_executionAddress"); err != nil {
		t.Logf("%s eth_executionAddress: %v", endpoint, err)
	} else {
		addrs = append(addrs, exec...)
	}
	var coinbase common.Address
	if err := client.CallContext(ctx, &coinbase, "eth_coinbase"); err != nil {
		t.Logf("%s eth_coinbase: %v", endpoint, err)
	} else if coinbase != (common.Address{}) {
		addrs = append(addrs, coinbase)
	}
	addrs = uniqueAddrs(addrs)

	msg := hexutil.Bytes("suave-dev-exposure")
	for _, addr := range addrs {
		args := signingArgs(addr)

		var signed struct {
			Raw hexutil.Bytes `json:"raw"`
		}
		err := client.CallContext(ctx, &signed, "eth_signTransaction", args)
		if err != nil {
			t.Logf("%s eth_signTransaction %s: %v", endpoint, addr.Hex(), err)
		} else if len(signed.Raw) > 0 {
			recovered, recErr := recoverTxSender(signed.Raw)
			var txHash common.Hash
			sendErr := client.CallContext(ctx, &txHash, "eth_sendRawTransaction", signed.Raw)
			t.Errorf("%s eth_signTransaction signed a transaction for %s (recovered %s, recover err %v, published key %v); eth_sendRawTransaction err %v hash %s",
				endpoint, addr.Hex(), recovered.Hex(), recErr, recovered == published || addr == published, sendErr, txHash.Hex())
		}

		var sig hexutil.Bytes
		err = client.CallContext(ctx, &sig, "eth_sign", addr, msg)
		if err != nil {
			t.Logf("%s eth_sign %s: %v", endpoint, addr.Hex(), err)
		} else if len(sig) > 0 {
			recovered, recErr := recoverTextSignature(msg, sig)
			t.Errorf("%s eth_sign returned a signature for %s (recovered %s, recover err %v, published key %v)",
				endpoint, addr.Hex(), recovered.Hex(), recErr, recovered == published || addr == published)
		}

		var sent common.Hash
		err = client.CallContext(ctx, &sent, "eth_sendTransaction", args)
		if err != nil {
			t.Logf("%s eth_sendTransaction %s: %v", endpoint, addr.Hex(), err)
		} else {
			t.Errorf("%s eth_sendTransaction accepted %s from %s", endpoint, sent.Hex(), addr.Hex())
		}

		err = client.CallContext(ctx, &signed, "personal_signTransaction", args, "")
		if err != nil {
			t.Logf("%s personal_signTransaction %s: %v", endpoint, addr.Hex(), err)
		} else if len(signed.Raw) > 0 {
			recovered, recErr := recoverTxSender(signed.Raw)
			t.Errorf("%s personal_signTransaction with an empty password signed for %s (recovered %s, recover err %v)",
				endpoint, addr.Hex(), recovered.Hex(), recErr)
		}

		err = client.CallContext(ctx, &sig, "personal_sign", msg, addr, "")
		if err != nil {
			t.Logf("%s personal_sign %s: %v", endpoint, addr.Hex(), err)
		} else if len(sig) > 0 {
			recovered, recErr := recoverTextSignature(msg, sig)
			t.Errorf("%s personal_sign with an empty password signed for %s (recovered %s, recover err %v)",
				endpoint, addr.Hex(), recovered.Hex(), recErr)
		}

		err = client.CallContext(ctx, &sent, "personal_sendTransaction", args, "")
		if err != nil {
			t.Logf("%s personal_sendTransaction %s: %v", endpoint, addr.Hex(), err)
		} else {
			t.Errorf("%s personal_sendTransaction with an empty password accepted %s from %s", endpoint, sent.Hex(), addr.Hex())
		}
	}
}

func signingArgs(from common.Address) ethapi.TransactionArgs {
	gas := hexutil.Uint64(21000)
	nonce := hexutil.Uint64(0)
	gasPrice := hexutil.Big(*big.NewInt(2_000_000_000))
	value := hexutil.Big(*big.NewInt(0))
	to := common.HexToAddress("0x0000000000000000000000000000000000000001")
	return ethapi.TransactionArgs{
		From:     &from,
		To:       &to,
		Gas:      &gas,
		GasPrice: &gasPrice,
		Nonce:    &nonce,
		Value:    &value,
	}
}

func recoverTxSender(raw []byte) (common.Address, error) {
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(raw); err != nil {
		return common.Address{}, err
	}
	return types.Sender(types.LatestSignerForChainID(tx.ChainId()), tx)
}

func recoverTextSignature(message, sig []byte) (common.Address, error) {
	if len(sig) != crypto.SignatureLength {
		return common.Address{}, errBadSignature
	}
	sig = append([]byte(nil), sig...)
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	pub, err := crypto.SigToPub(accounts.TextHash(message), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pub), nil
}

var errBadSignature = errString("signature has the wrong length")

type errString string

func (e errString) Error() string { return string(e) }

func uniqueAddrs(in []common.Address) []common.Address {
	seen := make(map[common.Address]struct{}, len(in))
	out := make([]common.Address, 0, len(in))
	for _, addr := range in {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func nonLoopbackIPv4(t *testing.T) []string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP.To4()
			case *net.IPAddr:
				ip = a.IP.To4()
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	if len(out) == 0 {
		t.Fatal("no non-loopback IPv4 address is available to dial")
	}
	return out
}

func listeningAddrs(t *testing.T, port int) []net.IP {
	t.Helper()
	var ips []net.IP
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		first := true
		for scanner.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			ip, p, ok := parseProcAddr(fields[1])
			if ok && p == port {
				ips = append(ips, ip)
			}
		}
		f.Close()
	}
	return ips
}

func parseProcAddr(raw string) (net.IP, int, bool) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return nil, 0, false
	}
	portBytes, err := hex.DecodeString(parts[1])
	if err != nil || len(portBytes) != 2 {
		return nil, 0, false
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	switch len(parts[0]) {
	case 8:
		b, err := hex.DecodeString(parts[0])
		if err != nil || len(b) != 4 {
			return nil, 0, false
		}
		return net.IPv4(b[3], b[2], b[1], b[0]), port, true
	case 32:
		b, err := hex.DecodeString(parts[0])
		if err != nil || len(b) != 16 {
			return nil, 0, false
		}
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				ip[i*4+j] = b[i*4+(3-j)]
			}
		}
		return ip, port, true
	default:
		return nil, 0, false
	}
}

func waitTCP(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
