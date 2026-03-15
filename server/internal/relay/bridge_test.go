package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func newTestBridge(t *testing.T) *Bridge {
	t.Helper()
	b := NewBridge(BridgeConfig{
		MaxChannelsTotal: 100,
		MaxMessageSize:   256 * 1024,
		PairingTTL:       10 * time.Minute,
		IdleTimeout:      60 * time.Second,
		ChallengeTimeout: 10 * time.Second,
		WaitPeerTimeout:  30 * time.Second,
	})
	t.Cleanup(b.Close)
	return b
}

// testServer creates a test HTTP server with the bridge handler.
func testServer(b *Bridge) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/connect", HandleConnect(b, 60*time.Second, 256*1024, false))
	return httptest.NewServer(mux)
}

// dial opens a WebSocket connection to the test server.
func dial(t *testing.T, s *httptest.Server) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(s.URL, "http") + "/v1/connect"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return ws
}

// send sends a JSON message over the websocket.
func send(t *testing.T, ws *websocket.Conn, msg interface{}) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ws.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// recv reads a JSON message from the websocket.
func recv(t *testing.T, ws *websocket.Conn) OutMsg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var msg OutMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return msg
}

// tryRecv tries to read a message with a short timeout, returns nil if none available.
func tryRecv(t *testing.T, ws *websocket.Conn, timeout time.Duration) *OutMsg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, data, err := ws.Read(ctx)
	if err != nil {
		return nil
	}
	var msg OutMsg
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}
	return &msg
}

func TestPairingFirstPeerWaits(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	send(t, ws, InMsg{
		Type:     "pair",
		Ch:       "pairing1",
		PubShare: b64.EncodeToString([]byte("pubshare-A")),
		ID:       "peer-A",
	})

	// No response expected - peer is waiting
	msg := tryRecv(t, ws, 200*time.Millisecond)
	if msg != nil {
		t.Fatalf("expected no message, got %+v", msg)
	}

	// Verify internal state
	b.mu.Lock()
	wp, exists := b.waitingPeers["pairing1"]
	b.mu.Unlock()

	if !exists {
		t.Fatal("expected waiting peer to be stored")
	}
	if wp.ID != "peer-A" {
		t.Fatalf("expected waiting peer ID 'peer-A', got %q", wp.ID)
	}
}

func TestPairingSecondPeerTriggerMatch(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// First peer
	send(t, ws1, InMsg{
		Type:     "pair",
		Ch:       "pairing1",
		PubShare: b64.EncodeToString([]byte("pubshare-A")),
		ID:       "peer-A",
	})

	// Second peer
	send(t, ws2, InMsg{
		Type:     "pair",
		Ch:       "pairing1",
		PubShare: b64.EncodeToString([]byte("pubshare-B")),
		ID:       "peer-B",
	})

	// Both should receive pair_matched
	msg1 := recv(t, ws1)
	msg2 := recv(t, ws2)

	if msg1.Type != "pair_matched" {
		t.Fatalf("expected pair_matched for peer1, got %q", msg1.Type)
	}
	if msg2.Type != "pair_matched" {
		t.Fatalf("expected pair_matched for peer2, got %q", msg2.Type)
	}

	// Identify which message is initiator and which is responder
	var initiator, responder OutMsg
	if msg1.Role == "initiator" {
		initiator, responder = msg1, msg2
	} else {
		initiator, responder = msg2, msg1
	}

	// Roles must be complementary
	if initiator.Role != "initiator" || responder.Role != "responder" {
		t.Fatalf("expected complementary roles, got %q and %q", initiator.Role, responder.Role)
	}

	// Each peer receives the OTHER peer's pubShare and id
	// (which peer is initiator depends on timing, so check cross-references)
	initPS, _ := b64.DecodeString(initiator.PubShare)
	respPS, _ := b64.DecodeString(responder.PubShare)
	if initiator.ID == responder.ID {
		t.Fatalf("both messages have same ID %q", initiator.ID)
	}
	// Initiator's ID field contains its peer (the responder's original ID)
	// Responder's ID field contains its peer (the initiator's original ID)
	// Just verify they are cross-referenced
	if (initiator.ID != "peer-A" && initiator.ID != "peer-B") ||
		(responder.ID != "peer-A" && responder.ID != "peer-B") {
		t.Fatalf("unexpected IDs: initiator=%q responder=%q", initiator.ID, responder.ID)
	}
	if string(initPS) == string(respPS) {
		t.Fatalf("both messages have same pubShare")
	}

	// Waiting peer should be removed
	b.mu.Lock()
	_, exists := b.waitingPeers["pairing1"]
	b.mu.Unlock()
	if exists {
		t.Fatal("expected waiting peer to be removed after match")
	}
}

func TestJoinCreatesChannelAndChallenges(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	send(t, ws, InMsg{Type: "join", Ch: "channel1", ID: "peer-A"})

	msg := recv(t, ws)
	if msg.Type != "challenge" {
		t.Fatalf("expected challenge, got %q", msg.Type)
	}
	if msg.Ch != "channel1" {
		t.Fatalf("expected ch=channel1, got %q", msg.Ch)
	}
	if msg.Nonce == "" {
		t.Fatal("expected nonce in challenge")
	}

	// Verify nonce is 32 bytes
	nonce, err := b64.DecodeString(msg.Nonce)
	if err != nil {
		t.Fatalf("invalid nonce encoding: %v", err)
	}
	if len(nonce) != 32 {
		t.Fatalf("expected 32-byte nonce, got %d", len(nonce))
	}
}

func TestSecondJoinReChallengesBoth(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// First peer joins
	send(t, ws1, InMsg{Type: "join", Ch: "channel1", ID: "peer-A"})
	challenge1 := recv(t, ws1)
	if challenge1.Type != "challenge" {
		t.Fatalf("expected challenge, got %q", challenge1.Type)
	}

	// Second peer joins
	send(t, ws2, InMsg{Type: "join", Ch: "channel1", ID: "peer-B"})

	// Peer1 gets a fresh challenge (re-challenged)
	reChallenge1 := recv(t, ws1)
	if reChallenge1.Type != "challenge" {
		t.Fatalf("expected re-challenge for peer1, got %q", reChallenge1.Type)
	}
	// Nonce should be different from original
	if reChallenge1.Nonce == challenge1.Nonce {
		t.Fatal("expected fresh nonce for re-challenge")
	}

	// Peer2 gets a challenge
	challenge2 := recv(t, ws2)
	if challenge2.Type != "challenge" {
		t.Fatalf("expected challenge for peer2, got %q", challenge2.Type)
	}
}

func TestBothResponsesTriggerVerifyPeer(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// Both join
	send(t, ws1, InMsg{Type: "join", Ch: "ch1", ID: "peer-A", Role: "initiator"})
	recv(t, ws1) // initial challenge

	send(t, ws2, InMsg{Type: "join", Ch: "ch1", ID: "peer-B", Role: "responder"})
	recv(t, ws1) // re-challenge for peer-A
	recv(t, ws2) // challenge for peer-B

	// Both respond
	send(t, ws1, InMsg{Type: "response", Ch: "ch1", Mac: b64.EncodeToString([]byte("mac-A"))})
	send(t, ws2, InMsg{Type: "response", Ch: "ch1", Mac: b64.EncodeToString([]byte("mac-B"))})

	// Both should receive verify_peer
	vp1 := recv(t, ws1)
	vp2 := recv(t, ws2)

	if vp1.Type != "verify_peer" {
		t.Fatalf("expected verify_peer for peer1, got %q", vp1.Type)
	}
	if vp2.Type != "verify_peer" {
		t.Fatalf("expected verify_peer for peer2, got %q", vp2.Type)
	}

	// Peer1 should get peer2's data
	if vp1.PeerID != "peer-B" {
		t.Fatalf("expected peerId=peer-B, got %q", vp1.PeerID)
	}
	if vp1.PeerRole != "responder" {
		t.Fatalf("expected peerRole=responder, got %q", vp1.PeerRole)
	}
	mac1, _ := b64.DecodeString(vp1.PeerMac)
	if string(mac1) != "mac-B" {
		t.Fatalf("expected mac-B, got %q", string(mac1))
	}

	// Peer2 should get peer1's data
	if vp2.PeerID != "peer-A" {
		t.Fatalf("expected peerId=peer-A, got %q", vp2.PeerID)
	}
	if vp2.PeerRole != "initiator" {
		t.Fatalf("expected peerRole=initiator, got %q", vp2.PeerRole)
	}
	mac2, _ := b64.DecodeString(vp2.PeerMac)
	if string(mac2) != "mac-A" {
		t.Fatalf("expected mac-A, got %q", string(mac2))
	}
}

func TestMessageRelayOnlyWhenActive(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// Setup active channel
	setupActiveChannel(t, ws1, ws2, "ch1", "peer-A", "peer-B")

	// Send message from peer-A to peer-B
	send(t, ws1, InMsg{Type: "message", Ch: "ch1", Data: b64.EncodeToString([]byte("hello"))})

	msg := recv(t, ws2)
	if msg.Type != "message" {
		t.Fatalf("expected message, got %q", msg.Type)
	}
	if msg.PeerID != "peer-A" {
		t.Fatalf("expected peerId=peer-A, got %q", msg.PeerID)
	}
	data, _ := b64.DecodeString(msg.Data)
	if string(data) != "hello" {
		t.Fatalf("expected 'hello', got %q", string(data))
	}
}

func TestMessageRelayRejectedBeforeActive(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	// Join but don't complete challenge-response
	send(t, ws, InMsg{Type: "join", Ch: "ch1", ID: "peer-A"})
	recv(t, ws) // challenge

	// Try to send message
	send(t, ws, InMsg{Type: "message", Ch: "ch1", Data: b64.EncodeToString([]byte("hello"))})

	msg := recv(t, ws)
	if msg.Type != "error" {
		t.Fatalf("expected error, got %q", msg.Type)
	}
}

func TestLeaveNotifiesOtherPeer(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	setupActiveChannel(t, ws1, ws2, "ch1", "peer-A", "peer-B")

	// Peer-A leaves
	send(t, ws1, InMsg{Type: "leave", Ch: "ch1"})

	// Peer-B should receive peer_left
	msg := recv(t, ws2)
	if msg.Type != "peer_left" {
		t.Fatalf("expected peer_left, got %q", msg.Type)
	}
	if msg.PeerID != "peer-A" {
		t.Fatalf("expected peerId=peer-A, got %q", msg.PeerID)
	}
}

func TestDisconnectSendsPeerLeft(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	setupActiveChannel(t, ws1, ws2, "ch1", "peer-A", "peer-B")

	// Peer-A disconnects
	ws1.Close(websocket.StatusNormalClosure, "bye")

	// Peer-B should receive peer_left
	msg := recv(t, ws2)
	if msg.Type != "peer_left" {
		t.Fatalf("expected peer_left, got %q", msg.Type)
	}
}

func TestConnectionReplacement(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// Peer-A joins
	send(t, ws1, InMsg{Type: "join", Ch: "ch1", ID: "peer-A"})
	recv(t, ws1) // challenge

	// New connection with same ID joins (replacement)
	ws3 := dial(t, s)
	defer ws3.Close(websocket.StatusNormalClosure, "")

	send(t, ws3, InMsg{Type: "join", Ch: "ch1", ID: "peer-A"})

	// Old connection should get "replaced" error
	msg := recv(t, ws1)
	if msg.Type != "error" || msg.Code != "replaced" {
		t.Fatalf("expected replaced error, got type=%q code=%q", msg.Type, msg.Code)
	}

	// New connection should get a challenge
	msg3 := recv(t, ws3)
	if msg3.Type != "challenge" {
		t.Fatalf("expected challenge for replacement, got %q", msg3.Type)
	}
}

func TestChannelFull(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")
	ws3 := dial(t, s)
	defer ws3.Close(websocket.StatusNormalClosure, "")

	// Two peers join
	send(t, ws1, InMsg{Type: "join", Ch: "ch1", ID: "peer-A"})
	recv(t, ws1) // challenge

	send(t, ws2, InMsg{Type: "join", Ch: "ch1", ID: "peer-B"})
	recv(t, ws1) // re-challenge
	recv(t, ws2) // challenge

	// Third peer tries to join
	send(t, ws3, InMsg{Type: "join", Ch: "ch1", ID: "peer-C"})

	msg := recv(t, ws3)
	if msg.Type != "error" || msg.Code != "channel_full" {
		t.Fatalf("expected channel_full error, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestVerifyRejectedDeletesChannel(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	setupActiveChannel(t, ws1, ws2, "ch1", "peer-A", "peer-B")

	// Peer-A sends verify_rejected
	send(t, ws1, InMsg{Type: "error", Code: "verify_rejected", Ch: "ch1"})

	// Peer-B should get the rejection
	msg := recv(t, ws2)
	if msg.Type != "error" || msg.Code != "verify_rejected" {
		t.Fatalf("expected verify_rejected, got type=%q code=%q", msg.Type, msg.Code)
	}

	// Channel should be deleted
	time.Sleep(50 * time.Millisecond)
	b.mu.Lock()
	_, exists := b.channels["ch1"]
	b.mu.Unlock()
	if exists {
		t.Fatal("expected channel to be deleted after verify_rejected")
	}
}

func TestDisconnectCleansUpAllChannels(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")
	ws3 := dial(t, s)
	defer ws3.Close(websocket.StatusNormalClosure, "")

	// Peer-A in two channels
	setupActiveChannel(t, ws1, ws2, "ch1", "peer-A", "peer-B")
	setupActiveChannel(t, ws1, ws3, "ch2", "peer-A", "peer-C")

	// Peer-A disconnects
	ws1.Close(websocket.StatusNormalClosure, "bye")

	// Both peers should get peer_left
	msg2 := recv(t, ws2)
	if msg2.Type != "peer_left" {
		t.Fatalf("expected peer_left on ch1, got %q", msg2.Type)
	}
	msg3 := recv(t, ws3)
	if msg3.Type != "peer_left" {
		t.Fatalf("expected peer_left on ch2, got %q", msg3.Type)
	}
}

func TestRejoinAfterDisconnect(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	setupActiveChannel(t, ws1, ws2, "ch1", "peer-A", "peer-B")

	// Peer-A disconnects
	ws1.Close(websocket.StatusNormalClosure, "bye")
	recv(t, ws2) // peer_left

	// Peer-A reconnects with new WebSocket
	ws1New := dial(t, s)
	defer ws1New.Close(websocket.StatusNormalClosure, "")

	send(t, ws1New, InMsg{Type: "join", Ch: "ch1", ID: "peer-A", Role: "initiator"})

	// Both should be re-challenged
	ch1 := ws1New
	ch2 := ws2

	msg1 := recv(t, ch1)
	msg2 := recv(t, ch2)

	if msg1.Type != "challenge" {
		t.Fatalf("expected challenge for rejoining peer, got %q", msg1.Type)
	}
	if msg2.Type != "challenge" {
		t.Fatalf("expected re-challenge for remaining peer, got %q", msg2.Type)
	}

	// Both respond
	send(t, ch1, InMsg{Type: "response", Ch: "ch1", Mac: b64.EncodeToString([]byte("mac-new")), Role: "initiator"})
	send(t, ch2, InMsg{Type: "response", Ch: "ch1", Mac: b64.EncodeToString([]byte("mac-B2")), Role: "responder"})

	recv(t, ch1) // verify_peer
	recv(t, ch2) // verify_peer

	// Relay should work again
	send(t, ch1, InMsg{Type: "message", Ch: "ch1", Data: b64.EncodeToString([]byte("reconnected"))})
	relayed := recv(t, ch2)
	if relayed.Type != "message" {
		t.Fatalf("expected relayed message after rejoin, got %q", relayed.Type)
	}
	data, _ := b64.DecodeString(relayed.Data)
	if string(data) != "reconnected" {
		t.Fatalf("expected 'reconnected', got %q", string(data))
	}
}

func TestBidirectionalRelay(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	setupActiveChannel(t, ws1, ws2, "ch1", "peer-A", "peer-B")

	// A -> B
	send(t, ws1, InMsg{Type: "message", Ch: "ch1", Data: b64.EncodeToString([]byte("hello-from-A"))})
	msg := recv(t, ws2)
	if msg.PeerID != "peer-A" {
		t.Fatalf("expected peerId=peer-A, got %q", msg.PeerID)
	}
	d, _ := b64.DecodeString(msg.Data)
	if string(d) != "hello-from-A" {
		t.Fatalf("expected 'hello-from-A', got %q", string(d))
	}

	// B -> A
	send(t, ws2, InMsg{Type: "message", Ch: "ch1", Data: b64.EncodeToString([]byte("hello-from-B"))})
	msg = recv(t, ws1)
	if msg.PeerID != "peer-B" {
		t.Fatalf("expected peerId=peer-B, got %q", msg.PeerID)
	}
	d, _ = b64.DecodeString(msg.Data)
	if string(d) != "hello-from-B" {
		t.Fatalf("expected 'hello-from-B', got %q", string(d))
	}
}

func TestMultipleChannelsOnSameConnection(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")
	ws3 := dial(t, s)
	defer ws3.Close(websocket.StatusNormalClosure, "")

	// ws1 <-> ws2 on ch1
	setupActiveChannel(t, ws1, ws2, "ch1", "peer-A", "peer-B")
	// ws1 <-> ws3 on ch2
	setupActiveChannel(t, ws1, ws3, "ch2", "peer-A", "peer-C")

	// Message on ch1 goes to ws2
	send(t, ws1, InMsg{Type: "message", Ch: "ch1", Data: b64.EncodeToString([]byte("for-B"))})
	msg := recv(t, ws2)
	d, _ := b64.DecodeString(msg.Data)
	if string(d) != "for-B" {
		t.Fatalf("expected 'for-B', got %q", string(d))
	}

	// Message on ch2 goes to ws3
	send(t, ws1, InMsg{Type: "message", Ch: "ch2", Data: b64.EncodeToString([]byte("for-C"))})
	msg = recv(t, ws3)
	d, _ = b64.DecodeString(msg.Data)
	if string(d) != "for-C" {
		t.Fatalf("expected 'for-C', got %q", string(d))
	}

	// ws3 should not receive ch1 messages
	extra := tryRecv(t, ws3, 100*time.Millisecond)
	if extra != nil {
		t.Fatalf("ws3 should not receive ch1 messages, got %+v", extra)
	}
}

func TestInvalidMessageReturnsError(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	// Missing required fields
	send(t, ws, InMsg{Type: "pair"})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != "invalid_message" {
		t.Fatalf("expected invalid_message error, got type=%q code=%q", msg.Type, msg.Code)
	}

	// Unknown type
	send(t, ws, InMsg{Type: "unknown_type"})
	msg = recv(t, ws)
	if msg.Type != "error" || msg.Code != "invalid_message" {
		t.Fatalf("expected invalid_message error for unknown type, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestHealthzEndpoint(t *testing.T) {
	b := newTestBridge(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/connect", HandleConnect(b, 60*time.Second, 256*1024, false))
	s := httptest.NewServer(mux)
	defer s.Close()

	resp, err := http.Get(s.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestPairingFullFlow(t *testing.T) {
	// Full flow: pair -> join -> challenge -> response -> verify_peer -> message
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// Pairing
	send(t, ws1, InMsg{Type: "pair", Ch: "p1", PubShare: b64.EncodeToString([]byte("shareA")), ID: "peer-A"})
	send(t, ws2, InMsg{Type: "pair", Ch: "p1", PubShare: b64.EncodeToString([]byte("shareB")), ID: "peer-B"})
	pm1 := recv(t, ws1)
	pm2 := recv(t, ws2)
	if pm1.Type != "pair_matched" || pm2.Type != "pair_matched" {
		t.Fatal("pairing failed")
	}

	// Both derive channelId (simulated)
	chID := "derived-channel-123"

	// Join
	setupActiveChannel(t, ws1, ws2, chID, "peer-A", "peer-B")

	// Message relay
	send(t, ws1, InMsg{Type: "message", Ch: chID, Data: b64.EncodeToString([]byte("e2e-test"))})
	msg := recv(t, ws2)
	d, _ := b64.DecodeString(msg.Data)
	if string(d) != "e2e-test" {
		t.Fatalf("expected 'e2e-test', got %q", string(d))
	}
}

func TestLeaveOnePeerChannelSurvives(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	setupActiveChannel(t, ws1, ws2, "ch1", "peer-A", "peer-B")

	// Peer-A leaves
	send(t, ws1, InMsg{Type: "leave", Ch: "ch1"})
	recv(t, ws2) // peer_left

	// Channel should still exist (peer-B is still in it)
	b.mu.Lock()
	ch, exists := b.channels["ch1"]
	b.mu.Unlock()
	if !exists {
		t.Fatal("channel should still exist with one peer")
	}
	ch.mu.Lock()
	if ch.State != StateWaitPeer {
		t.Fatalf("expected WAIT_PEER state, got %q", ch.State)
	}
	ch.mu.Unlock()
}

func TestMaxPairingsPerIPRateLimit(t *testing.T) {
	b := NewBridge(BridgeConfig{
		MaxChannelsTotal: 100,
		MaxMessageSize:   256 * 1024,
		PairingTTL:       10 * time.Minute,
		IdleTimeout:      60 * time.Second,
		ChallengeTimeout: 10 * time.Second,
		WaitPeerTimeout:  30 * time.Second,
		MaxPairingsPerIP: 5,
	})
	t.Cleanup(b.Close)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	for i := 0; i < 5; i++ {
		send(t, ws, InMsg{
			Type:     "pair",
			Ch:       fmt.Sprintf("pair-%d", i),
			PubShare: b64.EncodeToString([]byte("pub")),
			ID:       "peer",
		})
	}

	// 6th should be rate limited
	send(t, ws, InMsg{
		Type:     "pair",
		Ch:       "pair-5",
		PubShare: b64.EncodeToString([]byte("pub")),
		ID:       "peer",
	})

	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != "rate_limited" {
		t.Fatalf("expected rate_limited, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestMaxChannelsPerIPRateLimit(t *testing.T) {
	b := NewBridge(BridgeConfig{
		MaxChannelsTotal: 100,
		MaxMessageSize:   256 * 1024,
		PairingTTL:       10 * time.Minute,
		IdleTimeout:      60 * time.Second,
		ChallengeTimeout: 10 * time.Second,
		WaitPeerTimeout:  30 * time.Second,
		MaxChannelsPerIP: 20,
	})
	t.Cleanup(b.Close)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	for i := 0; i < 20; i++ {
		send(t, ws, InMsg{Type: "join", Ch: fmt.Sprintf("ch-%d", i), ID: "peer"})
		recv(t, ws) // challenge
	}

	// 21st should be rate limited
	send(t, ws, InMsg{Type: "join", Ch: "ch-20", ID: "peer"})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != "rate_limited" {
		t.Fatalf("expected rate_limited, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestWaitPeerTimeoutStaleGoroutine(t *testing.T) {
	b := NewBridge(BridgeConfig{
		MaxChannelsTotal: 100,
		MaxMessageSize:   256 * 1024,
		PairingTTL:       10 * time.Minute,
		IdleTimeout:      60 * time.Second,
		ChallengeTimeout: 10 * time.Second,
		WaitPeerTimeout:  300 * time.Millisecond, // short for testing
	})
	t.Cleanup(b.Close)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// Peer A joins → WAIT_PEER (starts timeout goroutine #1 with gen=1)
	send(t, ws1, InMsg{Type: "join", Ch: "ch1", ID: "peer-A"})
	recv(t, ws1) // challenge

	// Peer B joins → CHALLENGING → respond → ACTIVE (before 300ms)
	send(t, ws2, InMsg{Type: "join", Ch: "ch1", ID: "peer-B"})
	recv(t, ws1) // re-challenge
	recv(t, ws2) // challenge
	send(t, ws1, InMsg{Type: "response", Ch: "ch1", Mac: b64.EncodeToString([]byte("mac-A"))})
	send(t, ws2, InMsg{Type: "response", Ch: "ch1", Mac: b64.EncodeToString([]byte("mac-B"))})
	recv(t, ws1) // verify_peer
	recv(t, ws2) // verify_peer
	// Now ACTIVE

	// Peer A leaves → WAIT_PEER (starts timeout goroutine #2 with gen=2)
	// Record time so we know when goroutine #2 will fire
	send(t, ws1, InMsg{Type: "leave", Ch: "ch1"})
	recv(t, ws2) // peer_left

	// Wait for goroutine #1's timeout to fire (300ms from test start)
	// but NOT long enough for goroutine #2 (300ms from leave) to fire.
	// The join-challenge-response-leave sequence takes ~50ms, so goroutine #1
	// fires at ~300ms and goroutine #2 fires at ~350ms. Sleep 200ms after
	// the leave to land between them — goroutine #1 has fired, #2 has not.
	time.Sleep(250 * time.Millisecond)

	// Channel should still exist (goroutine #1 had gen=1, current gen=2)
	b.mu.Lock()
	_, exists := b.channels["ch1"]
	b.mu.Unlock()
	if !exists {
		t.Fatal("channel should still exist — stale goroutine #1 should not delete it")
	}
}

// setupActiveChannel sets up a fully active channel between two websockets.
func setupActiveChannel(t *testing.T, ws1, ws2 *websocket.Conn, chID, id1, id2 string) {
	t.Helper()

	// Peer 1 joins
	send(t, ws1, InMsg{Type: "join", Ch: chID, ID: id1, Role: "initiator"})
	recv(t, ws1) // initial challenge

	// Peer 2 joins
	send(t, ws2, InMsg{Type: "join", Ch: chID, ID: id2, Role: "responder"})
	recv(t, ws1) // re-challenge for peer1
	recv(t, ws2) // challenge for peer2

	// Both respond
	send(t, ws1, InMsg{Type: "response", Ch: chID, Mac: b64.EncodeToString([]byte("mac-1"))})
	send(t, ws2, InMsg{Type: "response", Ch: chID, Mac: b64.EncodeToString([]byte("mac-2"))})

	// Both receive verify_peer
	recv(t, ws1)
	recv(t, ws2)
}
