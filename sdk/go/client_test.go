package latchrelay

import (
	"bytes"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func startServer(t *testing.T) (string, func()) {
	t.Helper()

	// Build the server binary from the server directory
	serverDir := "../../server"
	binPath := t.TempDir() + "/latch-relay"

	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = serverDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, out)
	}

	// Find a free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", port))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	serverURL := fmt.Sprintf("ws://127.0.0.1:%d/v1/connect", port)

	// Wait for server to be ready
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	cleanup := func() {
		cmd.Process.Kill()
		cmd.Wait()
	}

	return serverURL, cleanup
}

func TestPairingFlow(t *testing.T) {
	serverURL, cleanup := startServer(t)
	defer cleanup()

	// Use a fixed window so both clients derive the same keys
	pairingID, w := derivePairingKeysForWindow("TESTCODE", time.Now().Unix()/600)

	// Start two clients
	alice, err := NewClient(serverURL, "alice")
	if err != nil {
		t.Fatalf("alice connect: %v", err)
	}
	defer alice.Close()

	bob, err := NewClient(serverURL, "bob")
	if err != nil {
		t.Fatalf("bob connect: %v", err)
	}
	defer bob.Close()

	// Pair concurrently (both use same pairingID/w)
	var csAlice, csBob *ChannelState
	var errAlice, errBob error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		csAlice, errAlice = alice.PairDirect(pairingID, w)
	}()

	// Small delay to ensure alice's pair message arrives first (she becomes initiator)
	time.Sleep(100 * time.Millisecond)

	go func() {
		defer wg.Done()
		csBob, errBob = bob.PairDirect(pairingID, w)
	}()

	wg.Wait()

	if errAlice != nil {
		t.Fatalf("alice pair: %v", errAlice)
	}
	if errBob != nil {
		t.Fatalf("bob pair: %v", errBob)
	}

	// Both should have the same channelID and encKey
	if csAlice.ChannelID != csBob.ChannelID {
		t.Fatalf("channelID mismatch: alice=%s bob=%s", csAlice.ChannelID, csBob.ChannelID)
	}
	if !bytes.Equal(csAlice.EncKey, csBob.EncKey) {
		t.Fatal("encKey mismatch")
	}

	// Roles should be complementary
	if csAlice.Role == csBob.Role {
		t.Fatalf("roles should differ: alice=%s bob=%s", csAlice.Role, csBob.Role)
	}

	// Both should be active
	if !csAlice.Active || !csBob.Active {
		t.Fatal("channels should be active")
	}
}

func TestMessageRelay(t *testing.T) {
	serverURL, cleanup := startServer(t)
	defer cleanup()

	pairingID, w := derivePairingKeysForWindow("MSGTEST", time.Now().Unix()/600)

	alice, err := NewClient(serverURL, "alice")
	if err != nil {
		t.Fatalf("alice connect: %v", err)
	}
	defer alice.Close()

	bob, err := NewClient(serverURL, "bob")
	if err != nil {
		t.Fatalf("bob connect: %v", err)
	}
	defer bob.Close()

	// Set up message receiver for bob
	received := make(chan []byte, 1)
	bob.OnMessage(func(channelID string, peerID string, data []byte) {
		received <- data
	})

	// Pair
	var csAlice *ChannelState
	var errAlice, errBob error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		csAlice, errAlice = alice.PairDirect(pairingID, w)
	}()
	time.Sleep(100 * time.Millisecond)
	go func() {
		defer wg.Done()
		_, errBob = bob.PairDirect(pairingID, w)
	}()
	wg.Wait()

	if errAlice != nil {
		t.Fatalf("alice pair: %v", errAlice)
	}
	if errBob != nil {
		t.Fatalf("bob pair: %v", errBob)
	}

	// Send message from alice to bob
	msg := []byte("hello bob!")
	if err := alice.Send(csAlice.ChannelID, msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, msg) {
			t.Fatalf("message mismatch: got %q, want %q", got, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestPairWithCodeFunction(t *testing.T) {
	// Test that DerivePairingKeysForWindows returns valid keys
	current, previous := DerivePairingKeysForWindows("HELLO")

	if len(current.PairingID) != 64 {
		t.Fatalf("current pairingID length: %d", len(current.PairingID))
	}
	if current.W == nil || current.W.Sign() <= 0 {
		t.Fatal("current w invalid")
	}
	if len(previous.PairingID) != 64 {
		t.Fatalf("previous pairingID length: %d", len(previous.PairingID))
	}
	if previous.W == nil || previous.W.Sign() <= 0 {
		t.Fatal("previous w invalid")
	}

	// Current and previous should differ
	if current.PairingID == previous.PairingID {
		t.Fatal("current and previous should differ")
	}
}

func TestReconnection(t *testing.T) {
	serverURL, cleanup := startServer(t)
	defer cleanup()

	pairingID, w := derivePairingKeysForWindow("RECONN", time.Now().Unix()/600)

	alice, err := NewClient(serverURL, "alice")
	if err != nil {
		t.Fatalf("alice connect: %v", err)
	}

	bob, err := NewClient(serverURL, "bob")
	if err != nil {
		t.Fatalf("bob connect: %v", err)
	}

	// Pair
	var csAlice, csBob *ChannelState
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		csAlice, _ = alice.PairDirect(pairingID, w)
	}()
	time.Sleep(100 * time.Millisecond)
	go func() {
		defer wg.Done()
		csBob, _ = bob.PairDirect(pairingID, w)
	}()
	wg.Wait()

	if csAlice == nil || csBob == nil {
		t.Fatal("pairing failed")
	}

	channelID := csAlice.ChannelID
	encKey := csAlice.EncKey
	aliceRole := csAlice.Role

	// Disconnect alice
	alice.Close()
	time.Sleep(500 * time.Millisecond)

	// Reconnect alice
	alice2, err := NewClient(serverURL, "alice")
	if err != nil {
		t.Fatalf("alice2 connect: %v", err)
	}
	defer alice2.Close()
	defer bob.Close()

	// Set up message receiver
	received := make(chan []byte, 1)
	bob.OnMessage(func(ch string, peer string, data []byte) {
		received <- data
	})

	// Rejoin
	err = alice2.Rejoin(channelID, encKey, aliceRole)
	if err != nil {
		t.Fatalf("rejoin: %v", err)
	}

	// Send a message
	msg := []byte("i'm back!")
	if err := alice2.Send(channelID, msg); err != nil {
		t.Fatalf("send after rejoin: %v", err)
	}

	select {
	case got := <-received:
		if !bytes.Equal(got, msg) {
			t.Fatalf("message mismatch: got %q, want %q", got, msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message after rejoin")
	}
}

func TestSPAKE2WithDerivedW(t *testing.T) {
	// Test that SPAKE2 works with a w derived from PBKDF2+HKDF (realistic scenario)
	_, w := derivePairingKeysForWindow("REALCODE", 42)

	alice, _ := NewSPAKE2("initiator", w)
	bob, _ := NewSPAKE2("initiator", w)
	bob.Role = "responder"

	keA, err := alice.Finish(bob.PubShare(), "pid", "a", "b")
	if err != nil {
		t.Fatal(err)
	}
	keB, err := bob.Finish(alice.PubShare(), "pid", "b", "a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keA, keB) {
		t.Fatal("keys don't match with derived w")
	}
}

func TestSPAKE2LargeW(t *testing.T) {
	// w close to the curve order
	w := new(big.Int).Sub(p256N, big.NewInt(1))

	alice, _ := NewSPAKE2("initiator", w)
	bob, _ := NewSPAKE2("initiator", w)
	bob.Role = "responder"

	keA, err := alice.Finish(bob.PubShare(), "pid", "a", "b")
	if err != nil {
		t.Fatal(err)
	}
	keB, err := bob.Finish(alice.PubShare(), "pid", "b", "a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keA, keB) {
		t.Fatal("keys don't match with large w")
	}
}

func TestNewClientInvalidURL(t *testing.T) {
	// Completely invalid URL scheme
	_, err := NewClient("not-a-url", "test-id")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}

	// Unreachable host
	_, err = NewClient("ws://127.0.0.1:1/nonexistent", "test-id")
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}

	// Empty URL
	_, err = NewClient("", "test-id")
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestDerivePairingParamsBothWindows(t *testing.T) {
	current, previous := DerivePairingKeysForWindows("HELLO")

	// Both should produce valid 64-char hex pairingIDs
	if len(current.PairingID) != 64 {
		t.Fatalf("current pairingID length: got %d, want 64", len(current.PairingID))
	}
	if len(previous.PairingID) != 64 {
		t.Fatalf("previous pairingID length: got %d, want 64", len(previous.PairingID))
	}

	// Both w values must be valid non-zero scalars in [1, n)
	if current.W == nil || current.W.Sign() <= 0 {
		t.Fatal("current w is nil or non-positive")
	}
	if current.W.Cmp(p256N) >= 0 {
		t.Fatal("current w >= curve order")
	}
	if previous.W == nil || previous.W.Sign() <= 0 {
		t.Fatal("previous w is nil or non-positive")
	}
	if previous.W.Cmp(p256N) >= 0 {
		t.Fatal("previous w >= curve order")
	}

	// Current and previous must differ (different time windows)
	if current.PairingID == previous.PairingID {
		t.Fatal("current and previous pairingID should differ")
	}
	if current.W.Cmp(previous.W) == 0 {
		t.Fatal("current and previous w should differ")
	}

	// Calling again with same code should be deterministic (same time window)
	current2, previous2 := DerivePairingKeysForWindows("HELLO")
	if current.PairingID != current2.PairingID {
		t.Fatal("current pairingID not deterministic")
	}
	if current.W.Cmp(current2.W) != 0 {
		t.Fatal("current w not deterministic")
	}
	if previous.PairingID != previous2.PairingID {
		t.Fatal("previous pairingID not deterministic")
	}
	if previous.W.Cmp(previous2.W) != 0 {
		t.Fatal("previous w not deterministic")
	}

	// Case insensitive
	currentLower, _ := DerivePairingKeysForWindows("hello")
	if current.PairingID != currentLower.PairingID {
		t.Fatal("pairing derivation should be case insensitive")
	}
}

func TestSendOnUnknownChannel(t *testing.T) {
	// Create a minimal LatchClient without a real WebSocket connection
	// to test Send's channel lookup logic.
	c := &LatchClient{
		channels: make(map[string]*ChannelState),
		closed:   make(chan struct{}),
	}

	err := c.Send("nonexistent-channel", []byte("hello"))
	if err == nil {
		t.Fatal("expected error for unknown channel")
	}
}

func TestSendOnInactiveChannel(t *testing.T) {
	c := &LatchClient{
		channels: map[string]*ChannelState{
			"ch1": {
				ChannelID: "ch1",
				EncKey:    bytes.Repeat([]byte{0x42}, 32),
				Active:    false,
			},
		},
		closed: make(chan struct{}),
	}

	err := c.Send("ch1", []byte("hello"))
	if err == nil {
		t.Fatal("expected error for inactive channel")
	}
}

func TestChannelsReturnsCopy(t *testing.T) {
	original := &ChannelState{
		ChannelID: "ch1",
		EncKey:    []byte{1, 2, 3},
		Role:      "initiator",
		PeerID:    "peer1",
		Active:    true,
	}

	c := &LatchClient{
		channels: map[string]*ChannelState{"ch1": original},
		closed:   make(chan struct{}),
	}

	chs := c.Channels()

	// Should contain the channel
	if len(chs) != 1 {
		t.Fatalf("expected 1 channel, got %d", len(chs))
	}

	got := chs["ch1"]
	if got.ChannelID != "ch1" || got.Role != "initiator" {
		t.Fatal("channel data mismatch")
	}

	// Mutating the copy should not affect the original
	got.Active = false
	if !original.Active {
		t.Fatal("Channels() should return a deep copy")
	}
}

func TestClientIDAccessor(t *testing.T) {
	c := &LatchClient{id: "test-peer-id"}
	if c.ID() != "test-peer-id" {
		t.Fatalf("ID() = %q, want %q", c.ID(), "test-peer-id")
	}
}

// Cross-SDK compatibility test vectors.
// These values were generated using the Go SDK with known inputs and verified
// against the Node SDK's identical algorithm. Any change to the key derivation
// in either SDK should cause this test to fail.
func TestCrossSDKPairingKeyDerivation(t *testing.T) {
	// Vector 1: code="TESTCODE", window=100
	pairingID, w := derivePairingKeysForWindow("TESTCODE", 100)
	expectedPairingID := "f5dedd846ba42b0bd9a5007e8e4b389207b318dd0cb91cf4a6d8afbe5f1f3aad"
	expectedW := "4d54a247c68bbe7625e8ef068075fb60458756129b3bd041e0719923b863afb9"

	if pairingID != expectedPairingID {
		t.Fatalf("pairingID mismatch:\n  got:  %s\n  want: %s", pairingID, expectedPairingID)
	}
	wHex := fmt.Sprintf("%x", w)
	if wHex != expectedW {
		t.Fatalf("w mismatch:\n  got:  %s\n  want: %s", wHex, expectedW)
	}

	// Vector 2: code="CROSSTEST", window=42
	pairingID2, w2 := derivePairingKeysForWindow("CROSSTEST", 42)
	expectedPairingID2 := "8c014bda4dc926751411fd72ec45729f4d2f694755cf8da6ea0805db1a6a28d0"
	expectedW2 := "dd5cd5dc4680247e510ecf26e95dc7e645969b440e9dd4fa4b393c2a8f3b6ee0"

	if pairingID2 != expectedPairingID2 {
		t.Fatalf("pairingID2 mismatch:\n  got:  %s\n  want: %s", pairingID2, expectedPairingID2)
	}
	w2Hex := fmt.Sprintf("%x", w2)
	if w2Hex != expectedW2 {
		t.Fatalf("w2 mismatch:\n  got:  %s\n  want: %s", w2Hex, expectedW2)
	}
}

func TestCrossSDKDeriveChannelKeys(t *testing.T) {
	// Fixed Ke = repeat(0xAB, 32), pairingID = "test-pairing"
	ke := bytes.Repeat([]byte{0xAB}, 32)
	channelID, encKey := DeriveChannelKeys(ke, "test-pairing")

	expectedChannelID := "b5acadc39b84f9a7e81b786f49e3d9dcea5c4f81ee0c33804c22d29d364f3d84"
	expectedEncKey := "f02e25385caad091f3fb65e29b0f6849fd302e950880f812e9cf37d87a3338b8"

	if channelID != expectedChannelID {
		t.Fatalf("channelID mismatch:\n  got:  %s\n  want: %s", channelID, expectedChannelID)
	}
	encKeyHex := fmt.Sprintf("%x", encKey)
	if encKeyHex != expectedEncKey {
		t.Fatalf("encKey mismatch:\n  got:  %s\n  want: %s", encKeyHex, expectedEncKey)
	}
}

func TestCrossSDKChallengeMac(t *testing.T) {
	encKey := bytes.Repeat([]byte{0xCD}, 32)
	nonce := bytes.Repeat([]byte{0x01}, 32)
	mac := ComputeChallengeMac(encKey, "test-channel", nonce, "peer1", "initiator")

	expectedMAC := "6bfc9c5ac9d0293371080e7f05ebfcf05e687e9a6b0ca313f6e8a9b8e2b9d507"
	macHex := fmt.Sprintf("%x", mac)
	if macHex != expectedMAC {
		t.Fatalf("MAC mismatch:\n  got:  %s\n  want: %s", macHex, expectedMAC)
	}
}

func TestCrossSDKEncryptDecryptFormat(t *testing.T) {
	// Verify that the Go SDK's ciphertext format (nonce || ciphertext || tag)
	// matches the Node SDK's format, so cross-SDK decryption works.
	key := bytes.Repeat([]byte{0x42}, 32)
	channelID := "cross-sdk-channel"
	plaintext := []byte("cross-sdk message")

	ct, err := Encrypt(key, plaintext, channelID)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Format: nonce(12) || encrypted(len(plaintext)) || tag(16)
	expectedLen := 12 + len(plaintext) + 16
	if len(ct) != expectedLen {
		t.Fatalf("ciphertext length: got %d, want %d", len(ct), expectedLen)
	}

	// Decrypt should round-trip
	pt, err := Decrypt(key, ct, channelID)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", pt, plaintext)
	}

	// Empty plaintext should also work (Node SDK supports this)
	ctEmpty, err := Encrypt(key, []byte{}, channelID)
	if err != nil {
		t.Fatalf("encrypt empty: %v", err)
	}
	// nonce(12) + tag(16) = 28 bytes minimum
	if len(ctEmpty) != 28 {
		t.Fatalf("empty ciphertext length: got %d, want 28", len(ctEmpty))
	}
	ptEmpty, err := Decrypt(key, ctEmpty, channelID)
	if err != nil {
		t.Fatalf("decrypt empty: %v", err)
	}
	if len(ptEmpty) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(ptEmpty))
	}
}
