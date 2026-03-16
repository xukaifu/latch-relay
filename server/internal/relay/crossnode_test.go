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
