package relay

import (
	"sync"
	"time"
)

// MemoryBackend implements Backend using in-memory maps.
type MemoryBackend struct {
	mu           sync.Mutex
	waitingPeers map[string]*waitingEntry
}

type waitingEntry struct {
	info    PairingInfo
	created time.Time
}

// NewMemoryBackend creates a new in-memory backend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		waitingPeers: make(map[string]*waitingEntry),
	}
}

func (m *MemoryBackend) StorePairing(pairingId string, peer PairingInfo) (*PairingMatch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.waitingPeers[pairingId]
	if !ok {
		m.waitingPeers[pairingId] = &waitingEntry{
			info:    peer,
			created: time.Now(),
		}
		return nil, nil
	}

	// Match found — remove waiting entry and return both peers.
	delete(m.waitingPeers, pairingId)
	return &PairingMatch{
		Initiator: existing.info,
		Responder: peer,
	}, nil
}

func (m *MemoryBackend) RemovePairing(pairingId string, conn *Connection) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.waitingPeers[pairingId]
	if ok && entry.info.Conn == conn {
		delete(m.waitingPeers, pairingId)
	}
}

func (m *MemoryBackend) RemovePairingsByConn(conn *Connection) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, entry := range m.waitingPeers {
		if entry.info.Conn == conn {
			delete(m.waitingPeers, id)
		}
	}
}

func (m *MemoryBackend) CleanupPairings(ttl time.Duration) []ExpiredPairing {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var expired []ExpiredPairing
	for id, entry := range m.waitingPeers {
		if now.Sub(entry.created) > ttl {
			expired = append(expired, ExpiredPairing{
				Conn:      entry.info.Conn,
				PairingID: id,
			})
			delete(m.waitingPeers, id)
		}
	}
	return expired
}

func (m *MemoryBackend) PairingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.waitingPeers)
}

func (m *MemoryBackend) PopLocalPairing(pairingId string) *PairingInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.waitingPeers[pairingId]
	if !ok {
		return nil
	}
	delete(m.waitingPeers, pairingId)
	return &entry.info
}

func (m *MemoryBackend) RegisterChannelPeer(channelId, nodeId string) (bool, error) {
	return false, nil // single node, never cross-node
}

func (m *MemoryBackend) UnregisterChannelPeer(channelId string) {}

func (m *MemoryBackend) NodeID() string { return "" }

// Publish is a no-op for single-node memory backend.
func (m *MemoryBackend) Publish(channelId string, msg []byte) error { return nil }

// Subscribe is a no-op for single-node memory backend.
func (m *MemoryBackend) Subscribe(handler func(channelId string, msg []byte)) error { return nil }

// Close is a no-op for memory backend.
func (m *MemoryBackend) Close() {}
