package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func TestCrossNodePairing(t *testing.T) {
	skipIfNoRedis(t)

	// Create two Bridge instances with different RedisBackends (simulating two nodes)
	rb1, err := NewRedisBackend("localhost:6379")
	if err != nil {
		t.Fatal(err)
	}
	rb2, err := NewRedisBackend("localhost:6379")
	if err != nil {
		t.Fatal(err)
	}

	cfg := BridgeConfig{
		MaxChannelsTotal: 100,
		MaxMessageSize:   256 * 1024,
		PairingTTL:       10 * time.Minute,
		IdleTimeout:      60 * time.Second,
		ChallengeTimeout: 10 * time.Second,
		WaitPeerTimeout:  30 * time.Second,
		Debug:            true,
	}

	cfg.Backend = rb1
	b1 := NewBridge(cfg)
	t.Cleanup(b1.Close)

	cfg.Backend = rb2
	b2 := NewBridge(cfg)
	t.Cleanup(b2.Close)

	// Allow pub/sub subscriptions to establish
	time.Sleep(200 * time.Millisecond)

	s1 := httptest.NewServer(http.HandlerFunc(HandleConnect(b1, cfg.IdleTimeout, cfg.MaxMessageSize, false)))
	defer s1.Close()
	s2 := httptest.NewServer(http.HandlerFunc(HandleConnect(b2, cfg.IdleTimeout, cfg.MaxMessageSize, false)))
	defer s2.Close()

	// Connect client A to node 1
	wsURL1 := "ws" + strings.TrimPrefix(s1.URL, "http")
	wsA, _, err := websocket.Dial(context.Background(), wsURL1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer wsA.Close(websocket.StatusNormalClosure, "")

	// Connect client B to node 2
	wsURL2 := "ws" + strings.TrimPrefix(s2.URL, "http")
	wsB, _, err := websocket.Dial(context.Background(), wsURL2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer wsB.Close(websocket.StatusNormalClosure, "")

	pairingId := fmt.Sprintf("cross-test-%d-%d", time.Now().UnixNano(), time.Now().UnixMicro()%100000)

	// Clean up any stale Redis key
	ctx := context.Background()
	rb1.client.Del(ctx, redisPairingPrefix+pairingId)

	// Client A sends pair on node 1
	sendWS(t, wsA, InMsg{Type: "pair", Ch: pairingId, PubShare: b64.EncodeToString([]byte("pub-a")), ID: "alice"})

	// Give Redis time to store
	time.Sleep(100 * time.Millisecond)

	// Client B sends pair on node 2
	sendWS(t, wsB, InMsg{Type: "pair", Ch: pairingId, PubShare: b64.EncodeToString([]byte("pub-b")), ID: "bob"})

	// Both should receive pair_matched
	var wg sync.WaitGroup
	var msgA, msgB OutMsg

	wg.Add(2)
	go func() {
		defer wg.Done()
		msgA = recvWS(t, wsA)
	}()
	go func() {
		defer wg.Done()
		msgB = recvWS(t, wsB)
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for pair_matched")
	}

	if msgA.Type != "pair_matched" {
		t.Fatalf("client A: expected pair_matched, got %s (code=%s msg=%s)", msgA.Type, msgA.Code, msgA.Message)
	}
	if msgB.Type != "pair_matched" {
		t.Fatalf("client B: expected pair_matched, got %s (code=%s msg=%s)", msgB.Type, msgB.Code, msgB.Message)
	}

	t.Logf("Cross-node pairing successful: A=%s B=%s", msgA.Role, msgB.Role)
}

// TestCrossNodeFullFlow tests the complete cross-node flow by directly exercising
// the remote message handlers (handleRemoteJoinNotify, handleRemoteResponse,
// handleRemoteRelay, handleRemotePeerLeft). This is a white-box test that sets up
// channels with remote stubs to simulate cross-node communication.
func TestCrossNodeFullFlow(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	channelId := "crossnode-full-flow"

	// Local peer (Alice) joins
	send(t, ws, InMsg{Type: "join", Ch: channelId, ID: "alice", Role: "initiator"})
	challenge1 := recv(t, ws) // challenge (WAIT_PEER)
	if challenge1.Type != "challenge" {
		t.Fatalf("expected challenge, got %s", challenge1.Type)
	}

	// Simulate remote peer (Bob) joining via handleRemoteJoinNotify
	remoteNonce := []byte("remote-nonce-for-bob-0000000000")
	b.handleRemoteJoinNotify(channelId, RemoteJoinNotify{
		PeerID: "bob",
		Nonce:  remoteNonce,
	})

	// Alice should receive a re-challenge (fresh nonce)
	reChallenge := recv(t, ws)
	if reChallenge.Type != "challenge" {
		t.Fatalf("expected re-challenge after remote join, got %s (code=%s)", reChallenge.Type, reChallenge.Code)
	}

	// Alice responds to the challenge
	send(t, ws, InMsg{Type: "response", Ch: channelId, Mac: b64.EncodeToString([]byte("mac-alice")), Role: "initiator"})

	// Simulate remote peer (Bob) responding via handleRemoteResponse
	b.handleRemoteResponse(channelId, RemoteResponse{
		PeerID:   "bob",
		Role:     "responder",
		Nonce:    remoteNonce,
		Response: []byte("mac-bob"),
	})

	// Alice should receive verify_peer with Bob's data
	vp := recv(t, ws)
	if vp.Type != "verify_peer" {
		t.Fatalf("expected verify_peer, got %s (code=%s)", vp.Type, vp.Code)
	}
	if vp.PeerID != "bob" {
		t.Fatalf("expected peerId=bob, got %q", vp.PeerID)
	}
	if vp.PeerRole != "responder" {
		t.Fatalf("expected peerRole=responder, got %q", vp.PeerRole)
	}
	vpMac, _ := b64.DecodeString(vp.PeerMac)
	if string(vpMac) != "mac-bob" {
		t.Fatalf("expected peerMac=mac-bob, got %q", string(vpMac))
	}

	// Channel should be ACTIVE now
	b.mu.Lock()
	ch := b.channels[channelId]
	b.mu.Unlock()
	ch.mu.Lock()
	if ch.State != StateActive {
		t.Fatalf("expected ACTIVE state, got %s", ch.State)
	}
	ch.mu.Unlock()

	// Simulate remote peer sending a message via handleRemoteRelay
	b.handleRemoteRelay(channelId, RemoteRelay{
		PeerID: "bob",
		Data:   b64.EncodeToString([]byte("hello-from-bob")),
	})

	// Alice should receive the relayed message
	relayed := recv(t, ws)
	if relayed.Type != "message" {
		t.Fatalf("expected message, got %s", relayed.Type)
	}
	if relayed.PeerID != "bob" {
		t.Fatalf("expected peerId=bob, got %q", relayed.PeerID)
	}
	relayedData, _ := b64.DecodeString(relayed.Data)
	if string(relayedData) != "hello-from-bob" {
		t.Fatalf("expected 'hello-from-bob', got %q", string(relayedData))
	}

	// Simulate remote peer leaving via handleRemotePeerLeft
	b.handleRemotePeerLeft(channelId, RemotePeerLeft{PeerID: "bob"})

	// Alice should receive peer_left
	peerLeft := recv(t, ws)
	if peerLeft.Type != "peer_left" {
		t.Fatalf("expected peer_left, got %s", peerLeft.Type)
	}
	if peerLeft.PeerID != "bob" {
		t.Fatalf("expected peerId=bob in peer_left, got %q", peerLeft.PeerID)
	}
}

// TestCrossNodeMessageRelay tests bidirectional message relay with remote stubs.
// It sets up a channel where the local peer sends a message and the remote peer
// sends one back via handleRemoteRelay.
func TestCrossNodeMessageRelay(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	channelId := "crossnode-relay-test"

	// Local peer joins
	send(t, ws, InMsg{Type: "join", Ch: channelId, ID: "alice", Role: "initiator"})
	recv(t, ws) // challenge

	// Remote peer joins
	b.handleRemoteJoinNotify(channelId, RemoteJoinNotify{
		PeerID: "bob",
		Nonce:  []byte("remote-nonce-00000000000000000000"),
	})
	recv(t, ws) // re-challenge

	// Both respond
	send(t, ws, InMsg{Type: "response", Ch: channelId, Mac: b64.EncodeToString([]byte("mac-a")), Role: "initiator"})
	b.handleRemoteResponse(channelId, RemoteResponse{
		PeerID:   "bob",
		Role:     "responder",
		Nonce:    []byte("remote-nonce-00000000000000000000"),
		Response: []byte("mac-b"),
	})
	recv(t, ws) // verify_peer

	// Alice sends message to Bob (goes to remote peer via pub/sub, but we just verify state)
	send(t, ws, InMsg{Type: "message", Ch: channelId, Data: b64.EncodeToString([]byte("msg-a-to-b"))})

	// Bob sends message to Alice via handleRemoteRelay
	b.handleRemoteRelay(channelId, RemoteRelay{
		PeerID: "bob",
		Data:   b64.EncodeToString([]byte("msg-b-to-a")),
	})

	msgA := recv(t, ws)
	if msgA.Type != "message" {
		t.Fatalf("expected message, got %s", msgA.Type)
	}
	dataA, _ := b64.DecodeString(msgA.Data)
	if string(dataA) != "msg-b-to-a" {
		t.Fatalf("expected 'msg-b-to-a', got %q", string(dataA))
	}
	if msgA.PeerID != "bob" {
		t.Fatalf("expected peerId=bob, got %q", msgA.PeerID)
	}

	// Multiple messages from remote
	for i := 0; i < 5; i++ {
		payload := fmt.Sprintf("bulk-%d", i)
		b.handleRemoteRelay(channelId, RemoteRelay{
			PeerID: "bob",
			Data:   b64.EncodeToString([]byte(payload)),
		})
		got := recv(t, ws)
		d, _ := b64.DecodeString(got.Data)
		if string(d) != payload {
			t.Fatalf("bulk message %d: expected %q, got %q", i, payload, string(d))
		}
	}

	// Verify MessagesRelayed counter was incremented for Alice's outgoing message
	if b.MessagesRelayed.Load() < 1 {
		t.Fatalf("expected MessagesRelayed >= 1, got %d", b.MessagesRelayed.Load())
	}
}

func sendWS(t *testing.T, ws *websocket.Conn, msg InMsg) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ws.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
}

func recvWS(t *testing.T, ws *websocket.Conn) OutMsg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var msg OutMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatal(err)
	}
	return msg
}
