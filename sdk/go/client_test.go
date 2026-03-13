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
