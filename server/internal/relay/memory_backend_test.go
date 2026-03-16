package relay

import (
	"sync/atomic"
	"testing"
	"time"
)

func newTestConn(id string) *Connection {
	return &Connection{
		ID:       id,
		Channels: make(map[string]bool),
		bytesOut: &atomic.Int64{},
	}
}

func TestMemoryBackendStorePairingFirstPeer(t *testing.T) {
	mb := NewMemoryBackend()
	conn := newTestConn("c1")

	match, err := mb.StorePairing("p1", PairingInfo{
		Conn:     conn,
		ID:       "peer-A",
		PubShare: []byte("share-A"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match != nil {
		t.Fatal("expected nil match for first peer")
	}
	if mb.PairingCount() != 1 {
		t.Fatalf("expected count 1, got %d", mb.PairingCount())
	}
}

func TestMemoryBackendStorePairingMatch(t *testing.T) {
	mb := NewMemoryBackend()
	connA := newTestConn("c1")
	connB := newTestConn("c2")

	mb.StorePairing("p1", PairingInfo{
		Conn:     connA,
		ID:       "peer-A",
		PubShare: []byte("share-A"),
	})

	match, err := mb.StorePairing("p1", PairingInfo{
		Conn:     connB,
		ID:       "peer-B",
		PubShare: []byte("share-B"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if match == nil {
		t.Fatal("expected match, got nil")
	}
	if match.Initiator.ID != "peer-A" {
		t.Fatalf("expected initiator peer-A, got %q", match.Initiator.ID)
	}
	if match.Responder.ID != "peer-B" {
		t.Fatalf("expected responder peer-B, got %q", match.Responder.ID)
	}
	if mb.PairingCount() != 0 {
		t.Fatalf("expected count 0 after match, got %d", mb.PairingCount())
	}
}

func TestMemoryBackendRemovePairing(t *testing.T) {
	mb := NewMemoryBackend()
	conn := newTestConn("c1")

	mb.StorePairing("p1", PairingInfo{
		Conn:     conn,
		ID:       "peer-A",
		PubShare: []byte("share-A"),
	})

	// Remove with matching conn
	mb.RemovePairing("p1", conn)
	if mb.PairingCount() != 0 {
		t.Fatalf("expected count 0 after remove, got %d", mb.PairingCount())
	}

	// Second peer should not match (entry was removed)
	connB := newTestConn("c2")
	match, _ := mb.StorePairing("p1", PairingInfo{
		Conn:     connB,
		ID:       "peer-B",
		PubShare: []byte("share-B"),
	})
	if match != nil {
		t.Fatal("expected nil match after removal")
	}
}

func TestMemoryBackendRemovePairingWrongConn(t *testing.T) {
	mb := NewMemoryBackend()
	connA := newTestConn("c1")
	connB := newTestConn("c2")

	mb.StorePairing("p1", PairingInfo{
		Conn:     connA,
		ID:       "peer-A",
		PubShare: []byte("share-A"),
	})

	// Remove with wrong conn — should not remove
	mb.RemovePairing("p1", connB)
	if mb.PairingCount() != 1 {
		t.Fatalf("expected count 1 (wrong conn), got %d", mb.PairingCount())
	}
}

func TestMemoryBackendRemovePairingsByConn(t *testing.T) {
	mb := NewMemoryBackend()
	conn := newTestConn("c1")
	other := newTestConn("c2")

	mb.StorePairing("p1", PairingInfo{Conn: conn, ID: "a", PubShare: []byte("s")})
	mb.StorePairing("p2", PairingInfo{Conn: conn, ID: "b", PubShare: []byte("s")})
	mb.StorePairing("p3", PairingInfo{Conn: other, ID: "c", PubShare: []byte("s")})

	mb.RemovePairingsByConn(conn)
	if mb.PairingCount() != 1 {
		t.Fatalf("expected count 1, got %d", mb.PairingCount())
	}
}

func TestMemoryBackendCleanupPairings(t *testing.T) {
	mb := NewMemoryBackend()
	conn := newTestConn("c1")

	mb.StorePairing("p1", PairingInfo{Conn: conn, ID: "a", PubShare: []byte("s")})

	// Manually backdate the entry
	mb.mu.Lock()
	mb.waitingPeers["p1"].created = time.Now().Add(-2 * time.Minute)
	mb.mu.Unlock()

	// Add a fresh entry
	conn2 := newTestConn("c2")
	mb.StorePairing("p2", PairingInfo{Conn: conn2, ID: "b", PubShare: []byte("s")})

	expired := mb.CleanupPairings(1 * time.Minute)
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired, got %d", len(expired))
	}
	if expired[0].PairingID != "p1" {
		t.Fatalf("expected expired p1, got %q", expired[0].PairingID)
	}
	if expired[0].Conn != conn {
		t.Fatal("expected expired conn to match")
	}
	if mb.PairingCount() != 1 {
		t.Fatalf("expected count 1 after cleanup, got %d", mb.PairingCount())
	}
}

func TestMemoryBackendPairingCount(t *testing.T) {
	mb := NewMemoryBackend()

	if mb.PairingCount() != 0 {
		t.Fatalf("expected 0, got %d", mb.PairingCount())
	}

	c1 := newTestConn("c1")
	c2 := newTestConn("c2")
	c3 := newTestConn("c3")

	mb.StorePairing("p1", PairingInfo{Conn: c1, ID: "a", PubShare: []byte("s")})
	mb.StorePairing("p2", PairingInfo{Conn: c2, ID: "b", PubShare: []byte("s")})
	if mb.PairingCount() != 2 {
		t.Fatalf("expected 2, got %d", mb.PairingCount())
	}

	// Match p1 — count should drop to 1
	mb.StorePairing("p1", PairingInfo{Conn: c3, ID: "c", PubShare: []byte("s")})
	if mb.PairingCount() != 1 {
		t.Fatalf("expected 1 after match, got %d", mb.PairingCount())
	}
}
