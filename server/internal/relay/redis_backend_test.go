package relay

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func skipIfNoRedis(t *testing.T) {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping")
	}
	client.Close()
}

func newTestRedisBackend(t *testing.T) *RedisBackend {
	t.Helper()
	skipIfNoRedis(t)
	rb, err := NewRedisBackend("localhost:6379")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rb.Close)
	return rb
}

func TestRedisBackendStorePairingFirstPeer(t *testing.T) {
	rb := newTestRedisBackend(t)
	match, err := rb.StorePairing("redis-test-1", PairingInfo{ID: "alice", PubShare: []byte("pub-a")})
	if err != nil {
		t.Fatal(err)
	}
	if match != nil {
		t.Fatal("expected nil match for first peer")
	}
	if rb.PairingCount() != 1 {
		t.Fatalf("expected 1 waiting, got %d", rb.PairingCount())
	}

	// Clean up Redis key
	ctx := context.Background()
	rb.client.Del(ctx, redisPairingPrefix+"redis-test-1")
}

func TestRedisBackendLocalMatch(t *testing.T) {
	rb := newTestRedisBackend(t)

	// First peer
	rb.StorePairing("redis-test-2", PairingInfo{ID: "alice", PubShare: []byte("pub-a")})

	// Second peer on same node — should match locally
	match, err := rb.StorePairing("redis-test-2", PairingInfo{ID: "bob", PubShare: []byte("pub-b")})
	if err != nil {
		t.Fatal(err)
	}
	if match == nil {
		t.Fatal("expected local match")
	}
	if match.Initiator.ID != "alice" || match.Responder.ID != "bob" {
		t.Fatalf("unexpected match: initiator=%s responder=%s", match.Initiator.ID, match.Responder.ID)
	}
	if rb.PairingCount() != 0 {
		t.Fatalf("expected 0 waiting after match, got %d", rb.PairingCount())
	}
}

func TestRedisBackendRemovePairing(t *testing.T) {
	rb := newTestRedisBackend(t)
	conn := &Connection{Channels: make(map[string]bool)}

	rb.StorePairing("redis-test-3", PairingInfo{ID: "alice", Conn: conn, PubShare: []byte("pub-a")})
	rb.RemovePairing("redis-test-3", conn)

	if rb.PairingCount() != 0 {
		t.Fatalf("expected 0 after removal, got %d", rb.PairingCount())
	}

	// Should not find a match
	match, _ := rb.StorePairing("redis-test-3", PairingInfo{ID: "bob", PubShare: []byte("pub-b")})
	if match != nil {
		t.Fatal("expected no match after removal")
	}

	// Clean up
	ctx := context.Background()
	rb.client.Del(ctx, redisPairingPrefix+"redis-test-3")
}

func TestRedisBackendPubSub(t *testing.T) {
	rb1 := newTestRedisBackend(t)
	rb2 := newTestRedisBackend(t)

	received := make(chan string, 1)
	rb2.Subscribe(func(channelId string, msg []byte) {
		received <- channelId + ":" + string(msg)
	})

	// Give subscriber time to connect
	time.Sleep(100 * time.Millisecond)

	rb1.Publish("test-channel", []byte("hello"))

	select {
	case got := <-received:
		if got != "test-channel:hello" {
			t.Fatalf("unexpected message: %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for pub/sub message")
	}
}

func TestRedisBackendCleanupPairings(t *testing.T) {
	rb := newTestRedisBackend(t)
	conn := &Connection{Channels: make(map[string]bool)}

	rb.StorePairing("redis-test-4", PairingInfo{ID: "alice", Conn: conn, PubShare: []byte("pub-a")})

	// Not expired
	expired := rb.CleanupPairings(10 * time.Minute)
	if len(expired) != 0 {
		t.Fatal("expected no expired")
	}

	// Force expiration
	rb.mu.Lock()
	rb.local["redis-test-4"].created = time.Now().Add(-11 * time.Minute)
	rb.mu.Unlock()

	expired = rb.CleanupPairings(10 * time.Minute)
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired, got %d", len(expired))
	}

	// Clean up Redis key
	ctx := context.Background()
	rb.client.Del(ctx, redisPairingPrefix+"redis-test-4")
}
