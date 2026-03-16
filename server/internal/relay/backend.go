package relay

import "time"

// PairingInfo holds data for a waiting peer in the backend.
type PairingInfo struct {
	Conn     *Connection
	ID       string
	PubShare []byte
	NodeID   string // identifies which relay node holds this peer's connection
}

// PairingMatch is returned when two peers are matched.
type PairingMatch struct {
	Initiator PairingInfo // peer that was already waiting
	Responder PairingInfo // peer that just arrived
}

// ExpiredPairing holds info needed to notify an expired waiting peer.
type ExpiredPairing struct {
	Conn      *Connection
	PairingID string
}

// Backend abstracts pairing storage and cross-node messaging.
type Backend interface {
	// StorePairing stores a waiting peer. If a match already exists,
	// returns the PairingMatch and removes the waiting entry.
	// Returns nil match if no peer is waiting yet.
	StorePairing(pairingId string, peer PairingInfo) (*PairingMatch, error)

	// RemovePairing removes a waiting peer (e.g. on disconnect).
	// Only removes if the entry belongs to the given connection.
	RemovePairing(pairingId string, conn *Connection)

	// RemovePairingsByConn removes all waiting peers for a connection.
	RemovePairingsByConn(conn *Connection)

	// CleanupPairings removes entries older than ttl.
	CleanupPairings(ttl time.Duration) []ExpiredPairing

	// PairingCount returns the number of waiting peers.
	PairingCount() int

	// PopLocalPairing removes and returns a local waiting peer by pairingId.
	// Used when a remote node notifies us of a cross-node match.
	PopLocalPairing(pairingId string) *PairingInfo

	// RegisterChannelPeer registers that this node has a peer in a channel.
	// Returns true if another node already has a peer (cross-node channel).
	RegisterChannelPeer(channelId, nodeId string) (bool, error)

	// UnregisterChannelPeer removes channel registration for this node.
	UnregisterChannelPeer(channelId string)

	// Publish sends a message to other nodes for a channel.
	// No-op for single-node backends.
	Publish(channelId string, msg []byte) error

	// Subscribe registers a handler for messages from other nodes.
	// No-op for single-node backends.
	Subscribe(handler func(channelId string, msg []byte)) error

	// NodeID returns this node's unique identifier (empty for MemoryBackend).
	NodeID() string

	// Close shuts down the backend.
	Close()
}
