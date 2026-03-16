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

	// Verify internal state via backend
	if b.backend.PairingCount() != 1 {
		t.Fatalf("expected 1 waiting peer, got %d", b.backend.PairingCount())
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
	if b.backend.PairingCount() != 0 {
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

func TestStats(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	// Initial stats: zero connections, zero channels
	st := b.Stats()
	if st.Connections != 0 {
		t.Fatalf("expected 0 connections, got %d", st.Connections)
	}
	if st.Channels != 0 {
		t.Fatalf("expected 0 channels, got %d", st.Channels)
	}

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// After connecting, should have 2 connections
	time.Sleep(50 * time.Millisecond)
	st = b.Stats()
	if st.Connections != 2 {
		t.Fatalf("expected 2 connections, got %d", st.Connections)
	}
	if st.TotalConnections != 2 {
		t.Fatalf("expected TotalConnections=2, got %d", st.TotalConnections)
	}

	// First peer joins -> channel in WAIT_PEER
	send(t, ws1, InMsg{Type: "join", Ch: "stats-ch", ID: "peer-A"})
	recv(t, ws1) // challenge

	st = b.Stats()
	if st.Channels != 1 {
		t.Fatalf("expected 1 channel, got %d", st.Channels)
	}
	if st.ChannelsWaiting != 1 {
		t.Fatalf("expected 1 waiting channel, got %d", st.ChannelsWaiting)
	}

	// Second peer joins -> channel in CHALLENGING
	send(t, ws2, InMsg{Type: "join", Ch: "stats-ch", ID: "peer-B"})
	recv(t, ws1) // re-challenge
	recv(t, ws2) // challenge

	st = b.Stats()
	if st.ChannelsChallenging != 1 {
		t.Fatalf("expected 1 challenging channel, got %d", st.ChannelsChallenging)
	}

	// Both respond -> ACTIVE
	send(t, ws1, InMsg{Type: "response", Ch: "stats-ch", Mac: b64.EncodeToString([]byte("mac-A"))})
	send(t, ws2, InMsg{Type: "response", Ch: "stats-ch", Mac: b64.EncodeToString([]byte("mac-B"))})
	recv(t, ws1) // verify_peer
	recv(t, ws2) // verify_peer

	st = b.Stats()
	if st.ChannelsActive != 1 {
		t.Fatalf("expected 1 active channel, got %d", st.ChannelsActive)
	}

	// Relay a message and check counter
	send(t, ws1, InMsg{Type: "message", Ch: "stats-ch", Data: b64.EncodeToString([]byte("hello"))})
	recv(t, ws2)

	st = b.Stats()
	if st.MessagesRelayed != 1 {
		t.Fatalf("expected MessagesRelayed=1, got %d", st.MessagesRelayed)
	}
	if st.UptimeSeconds < 0 {
		t.Fatalf("expected non-negative uptime, got %d", st.UptimeSeconds)
	}
	if st.BytesIn <= 0 {
		t.Fatalf("expected positive BytesIn, got %d", st.BytesIn)
	}
	if st.BytesOut <= 0 {
		t.Fatalf("expected positive BytesOut, got %d", st.BytesOut)
	}
}

func TestChallengeTimeoutRemovesPeer(t *testing.T) {
	b := NewBridge(BridgeConfig{
		MaxChannelsTotal: 100,
		MaxMessageSize:   256 * 1024,
		PairingTTL:       10 * time.Minute,
		IdleTimeout:      60 * time.Second,
		ChallengeTimeout: 200 * time.Millisecond,
		WaitPeerTimeout:  30 * time.Second,
	})
	t.Cleanup(b.Close)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// Both join so we enter CHALLENGING state
	send(t, ws1, InMsg{Type: "join", Ch: "timeout-ch", ID: "peer-A"})
	recv(t, ws1) // initial challenge

	send(t, ws2, InMsg{Type: "join", Ch: "timeout-ch", ID: "peer-B"})
	recv(t, ws1) // re-challenge
	recv(t, ws2) // challenge

	// Only peer-A responds; peer-B does NOT respond
	send(t, ws1, InMsg{Type: "response", Ch: "timeout-ch", Mac: b64.EncodeToString([]byte("mac-A"))})

	// Wait for challenge timeout to fire
	time.Sleep(400 * time.Millisecond)

	// Peer-B should receive challenge_timeout error
	msg := tryRecv(t, ws2, 500*time.Millisecond)
	if msg == nil {
		t.Fatal("expected challenge_timeout error, got nothing")
	}
	if msg.Type != "error" || msg.Code != ErrChallengeTimeout {
		t.Fatalf("expected challenge_timeout error, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestWaitPeerTimeoutCleansChannel(t *testing.T) {
	b := NewBridge(BridgeConfig{
		MaxChannelsTotal: 100,
		MaxMessageSize:   256 * 1024,
		PairingTTL:       10 * time.Minute,
		IdleTimeout:      60 * time.Second,
		ChallengeTimeout: 10 * time.Second,
		WaitPeerTimeout:  200 * time.Millisecond,
	})
	t.Cleanup(b.Close)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	// One client joins, receives challenge, responds
	send(t, ws, InMsg{Type: "join", Ch: "wait-ch", ID: "peer-A"})
	recv(t, ws) // challenge

	// No second client joins. Wait for timeout.
	time.Sleep(400 * time.Millisecond)

	// Client should receive challenge_timeout (the waitPeerTimeout sends this code)
	msg := tryRecv(t, ws, 500*time.Millisecond)
	if msg == nil {
		t.Fatal("expected timeout error, got nothing")
	}
	if msg.Type != "error" || msg.Code != ErrChallengeTimeout {
		t.Fatalf("expected challenge_timeout error, got type=%q code=%q", msg.Type, msg.Code)
	}

	// Channel should be cleaned up
	time.Sleep(50 * time.Millisecond)
	b.mu.Lock()
	_, exists := b.channels["wait-ch"]
	b.mu.Unlock()
	if exists {
		t.Fatal("expected channel to be deleted after wait peer timeout")
	}
}

func TestHandleRemoteMsgDispatch(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	channelId := "remote-dispatch"

	// Set up a channel with a local peer and a remote stub
	send(t, ws, InMsg{Type: "join", Ch: channelId, ID: "local", Role: "initiator"})
	recv(t, ws) // challenge

	// Test join_notify via handleRemoteMsg
	joinData, _ := marshalRemoteMsg("join_notify", channelId, RemoteJoinNotify{
		PeerID: "remote",
		Nonce:  []byte("nonce-for-remote-peer-0000000000"),
	})
	b.handleRemoteMsg(channelId, joinData)
	reChallenge := recv(t, ws)
	if reChallenge.Type != "challenge" {
		t.Fatalf("join_notify dispatch: expected challenge, got %s", reChallenge.Type)
	}

	// Local responds
	send(t, ws, InMsg{Type: "response", Ch: channelId, Mac: b64.EncodeToString([]byte("mac-local")), Role: "initiator"})

	// Test response via handleRemoteMsg
	respData, _ := marshalRemoteMsg("response", channelId, RemoteResponse{
		PeerID:   "remote",
		Role:     "responder",
		Nonce:    []byte("nonce-for-remote-peer-0000000000"),
		Response: []byte("mac-remote"),
	})
	b.handleRemoteMsg(channelId, respData)
	vp := recv(t, ws)
	if vp.Type != "verify_peer" {
		t.Fatalf("response dispatch: expected verify_peer, got %s", vp.Type)
	}

	// Test relay via handleRemoteMsg
	relayData, _ := marshalRemoteMsg("relay", channelId, RemoteRelay{
		PeerID: "remote",
		Data:   b64.EncodeToString([]byte("relayed-msg")),
	})
	b.handleRemoteMsg(channelId, relayData)
	msg := recv(t, ws)
	if msg.Type != "message" {
		t.Fatalf("relay dispatch: expected message, got %s", msg.Type)
	}

	// Test peer_left via handleRemoteMsg
	leftData, _ := marshalRemoteMsg("peer_left", channelId, RemotePeerLeft{PeerID: "remote"})
	b.handleRemoteMsg(channelId, leftData)
	pl := recv(t, ws)
	if pl.Type != "peer_left" {
		t.Fatalf("peer_left dispatch: expected peer_left, got %s", pl.Type)
	}

	// Test invalid JSON (should not panic)
	b.handleRemoteMsg(channelId, []byte("invalid json"))

	// Test pair_matched via handleRemoteMsg (no waiting peer, just tests dispatch)
	pmData, _ := marshalRemoteMsg("pair_matched", "some-pairing", RemotePairMatched{
		PairingID:    "some-pairing",
		PeerID:       "someone",
		PeerPubShare: []byte("share"),
	})
	b.handleRemoteMsg("some-pairing", pmData) // no-op, no waiting peer
}

func TestClientIPTrustProxy(t *testing.T) {
	// Test with X-Forwarded-For
	req, _ := http.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	ip := clientIP(req, true)
	if ip != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1, got %q", ip)
	}

	// Test with X-Real-IP (no X-Forwarded-For)
	req2, _ := http.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "192.168.1.1:1234"
	req2.Header.Set("X-Real-IP", "10.0.0.3")
	ip2 := clientIP(req2, true)
	if ip2 != "10.0.0.3" {
		t.Fatalf("expected 10.0.0.3, got %q", ip2)
	}

	// Test without trust proxy - should use RemoteAddr
	ip3 := clientIP(req, false)
	if ip3 != "192.168.1.1" {
		t.Fatalf("expected 192.168.1.1, got %q", ip3)
	}

	// Test X-Forwarded-For single value
	req4, _ := http.NewRequest("GET", "/", nil)
	req4.RemoteAddr = "192.168.1.1:1234"
	req4.Header.Set("X-Forwarded-For", "10.0.0.5")
	ip4 := clientIP(req4, true)
	if ip4 != "10.0.0.5" {
		t.Fatalf("expected 10.0.0.5, got %q", ip4)
	}
}

func TestLeaveNonexistentChannel(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	// Leave a channel that doesn't exist - should not error
	send(t, ws, InMsg{Type: "leave", Ch: "nonexistent"})

	// Leave with missing ch
	send(t, ws, InMsg{Type: "leave"})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrInvalidMessage {
		t.Fatalf("expected invalid_message error, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestResponseToNonexistentChannel(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	// Response to channel that doesn't exist
	send(t, ws, InMsg{Type: "response", Ch: "nonexistent", Mac: b64.EncodeToString([]byte("mac"))})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrChannelNotFound {
		t.Fatalf("expected channel_not_found, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestMessageToNonexistentChannel(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	// Message to channel that doesn't exist
	send(t, ws, InMsg{Type: "message", Ch: "nonexistent", Data: b64.EncodeToString([]byte("data"))})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrChannelNotFound {
		t.Fatalf("expected channel_not_found, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestPairInvalidPubShareEncoding(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	send(t, ws, InMsg{Type: "pair", Ch: "p1", PubShare: "!!!invalid-base64!!!", ID: "peer"})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrInvalidMessage {
		t.Fatalf("expected invalid_message, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestResponseInvalidMacEncoding(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	send(t, ws, InMsg{Type: "join", Ch: "ch1", ID: "peer"})
	recv(t, ws) // challenge

	send(t, ws, InMsg{Type: "response", Ch: "ch1", Mac: "!!!invalid!!!"})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrInvalidMessage {
		t.Fatalf("expected invalid_message, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestFieldTooLong(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	longCh := strings.Repeat("x", maxChLen+1)

	// Pair with too-long ch
	send(t, ws, InMsg{Type: "pair", Ch: longCh, PubShare: b64.EncodeToString([]byte("pub")), ID: "peer"})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrInvalidMessage {
		t.Fatalf("expected invalid_message for long ch in pair, got type=%q code=%q", msg.Type, msg.Code)
	}

	// Join with too-long ch
	send(t, ws, InMsg{Type: "join", Ch: longCh, ID: "peer"})
	msg = recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrInvalidMessage {
		t.Fatalf("expected invalid_message for long ch in join, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestMaxChannelsTotalLimit(t *testing.T) {
	b := NewBridge(BridgeConfig{
		MaxChannelsTotal: 2,
		MaxMessageSize:   256 * 1024,
		PairingTTL:       10 * time.Minute,
		IdleTimeout:      60 * time.Second,
		ChallengeTimeout: 10 * time.Second,
		WaitPeerTimeout:  30 * time.Second,
	})
	t.Cleanup(b.Close)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	// Fill up channels
	send(t, ws, InMsg{Type: "join", Ch: "ch1", ID: "p1"})
	recv(t, ws) // challenge
	send(t, ws, InMsg{Type: "join", Ch: "ch2", ID: "p2"})
	recv(t, ws) // challenge

	// Third should fail
	send(t, ws, InMsg{Type: "join", Ch: "ch3", ID: "p3"})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrChannelFull {
		t.Fatalf("expected channel_full, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestResponseNotInChannel(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws1 := dial(t, s)
	defer ws1.Close(websocket.StatusNormalClosure, "")
	ws2 := dial(t, s)
	defer ws2.Close(websocket.StatusNormalClosure, "")

	// ws1 joins
	send(t, ws1, InMsg{Type: "join", Ch: "ch1", ID: "peer-A"})
	recv(t, ws1) // challenge

	// ws2 tries to respond to ch1 (not in channel)
	send(t, ws2, InMsg{Type: "response", Ch: "ch1", Mac: b64.EncodeToString([]byte("mac"))})
	msg := recv(t, ws2)
	if msg.Type != "error" || msg.Code != ErrNotInChannel {
		t.Fatalf("expected not_in_channel, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestResponseMissingFields(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	// Missing ch
	send(t, ws, InMsg{Type: "response", Mac: b64.EncodeToString([]byte("mac"))})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrInvalidMessage {
		t.Fatalf("expected invalid_message, got type=%q code=%q", msg.Type, msg.Code)
	}

	// Missing mac
	send(t, ws, InMsg{Type: "response", Ch: "ch1"})
	msg = recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrInvalidMessage {
		t.Fatalf("expected invalid_message, got type=%q code=%q", msg.Type, msg.Code)
	}
}

func TestMessageMissingFields(t *testing.T) {
	b := newTestBridge(t)
	s := testServer(b)
	defer s.Close()

	ws := dial(t, s)
	defer ws.Close(websocket.StatusNormalClosure, "")

	// Missing data
	send(t, ws, InMsg{Type: "message", Ch: "ch1"})
	msg := recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrInvalidMessage {
		t.Fatalf("expected invalid_message, got type=%q code=%q", msg.Type, msg.Code)
	}

	// Missing ch
	send(t, ws, InMsg{Type: "message", Data: "data"})
	msg = recv(t, ws)
	if msg.Type != "error" || msg.Code != ErrInvalidMessage {
		t.Fatalf("expected invalid_message, got type=%q code=%q", msg.Type, msg.Code)
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
