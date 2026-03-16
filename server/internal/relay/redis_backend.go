package relay

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisPairingPrefix = "latch:pair:"
	redisRelayPrefix   = "relay:"
)

// redisPairingData is the JSON-serialized form of a waiting peer in Redis.
type redisPairingData struct {
	ID       string `json:"id"`
	PubShare []byte `json:"pubShare"`
	NodeID   string `json:"nodeId"`
}

// RedisBackend implements Backend using Redis for cross-node pairing and messaging.
type RedisBackend struct {
	client *redis.Client
	nodeID string
	mu     sync.Mutex
	local  map[string]*waitingEntry // local-first pairing cache
	stop   chan struct{}
}

// NewRedisBackend creates a new Redis-backed backend.
func NewRedisBackend(redisURL string) (*RedisBackend, error) {
	opts, err := redis.ParseURL("redis://" + redisURL)
	if err != nil {
		opts = &redis.Options{Addr: redisURL}
	}
	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	// Generate unique nodeID
	idBytes := make([]byte, 8)
	rand.Read(idBytes)
	nodeID := fmt.Sprintf("node-%x", idBytes)

	rb := &RedisBackend{
		client: client,
		nodeID: nodeID,
		local:  make(map[string]*waitingEntry),
		stop:   make(chan struct{}),
	}
	return rb, nil
}

func (r *RedisBackend) StorePairing(pairingId string, peer PairingInfo) (*PairingMatch, error) {
	// Local-first: check local map
	r.mu.Lock()
	existing, ok := r.local[pairingId]
	if ok {
		// Match locally
		delete(r.local, pairingId)
		r.mu.Unlock()

		// Clean up Redis entry
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r.client.Del(ctx, redisPairingPrefix+pairingId)

		return &PairingMatch{
			Initiator: existing.info,
			Responder: peer,
		}, nil
	}

	// Store locally
	r.local[pairingId] = &waitingEntry{info: peer, created: time.Now()}
	r.mu.Unlock()

	// Also store in Redis for cross-node discovery
	data, err := json.Marshal(redisPairingData{
		ID:       peer.ID,
		PubShare: peer.PubShare,
		NodeID:   r.nodeID,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Atomically set our data and get the previous value (SET key value GET EX)
	key := redisPairingPrefix + pairingId
	existingData, err := r.client.SetArgs(ctx, key, data, redis.SetArgs{
		TTL: 10 * time.Minute,
		Get: true,
	}).Result()
	if err == redis.Nil {
		// No existing entry — we're the first peer
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Another node had a waiting peer — match across nodes
	var remoteData redisPairingData
	if err := json.Unmarshal([]byte(existingData), &remoteData); err != nil {
		return nil, err
	}

	// Clean up
	r.client.Del(ctx, key)
	r.mu.Lock()
	delete(r.local, pairingId)
	r.mu.Unlock()

	if remoteData.NodeID == r.nodeID {
		// Same node — should have been caught by local check, but handle gracefully
		return nil, nil
	}

	// Cross-node match: the remote peer's Connection is on another node.
	// We return the match with remote peer info; Bridge will need to
	// coordinate via pub/sub to deliver pair_matched to the remote peer.
	return &PairingMatch{
		Initiator: PairingInfo{
			ID:       remoteData.ID,
			PubShare: remoteData.PubShare,
			NodeID:   remoteData.NodeID,
			// Conn is nil — remote peer is on another node
		},
		Responder: peer,
	}, nil
}

func (r *RedisBackend) RemovePairing(pairingId string, conn *Connection) {
	r.mu.Lock()
	entry, ok := r.local[pairingId]
	if ok && entry.info.Conn == conn {
		delete(r.local, pairingId)
	}
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r.client.Del(ctx, redisPairingPrefix+pairingId)
}

func (r *RedisBackend) RemovePairingsByConn(conn *Connection) {
	r.mu.Lock()
	var toDelete []string
	for id, entry := range r.local {
		if entry.info.Conn == conn {
			toDelete = append(toDelete, id)
		}
	}
	for _, id := range toDelete {
		delete(r.local, id)
	}
	r.mu.Unlock()

	if len(toDelete) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		keys := make([]string, len(toDelete))
		for i, id := range toDelete {
			keys[i] = redisPairingPrefix + id
		}
		r.client.Del(ctx, keys...)
	}
}

func (r *RedisBackend) CleanupPairings(ttl time.Duration) []ExpiredPairing {
	// Local cleanup only; Redis entries have their own TTL
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	var expired []ExpiredPairing
	for id, entry := range r.local {
		if now.Sub(entry.created) > ttl {
			expired = append(expired, ExpiredPairing{
				Conn:      entry.info.Conn,
				PairingID: id,
			})
			delete(r.local, id)
		}
	}
	return expired
}

func (r *RedisBackend) PairingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.local)
}

func (r *RedisBackend) PopLocalPairing(pairingId string) *PairingInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.local[pairingId]
	if !ok {
		return nil
	}
	delete(r.local, pairingId)
	return &entry.info
}

func (r *RedisBackend) Publish(channelId string, msg []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return r.client.Publish(ctx, redisRelayPrefix+channelId, msg).Err()
}

func (r *RedisBackend) Subscribe(handler func(channelId string, msg []byte)) error {
	pubsub := r.client.PSubscribe(context.Background(), redisRelayPrefix+"*")

	go func() {
		defer pubsub.Close()
		ch := pubsub.Channel()
		for {
			select {
			case <-r.stop:
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				channelId := msg.Channel[len(redisRelayPrefix):]
				handler(channelId, []byte(msg.Payload))
			}
		}
	}()

	return nil
}

func (r *RedisBackend) Close() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	r.client.Close()
}
