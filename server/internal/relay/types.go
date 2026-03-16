package relay

import (
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

// Channel states
const (
	StateWaitPeer    = "WAIT_PEER"
	StateChallenging = "CHALLENGING"
	StateActive      = "ACTIVE"
)

// Error codes
const (
	ErrInvalidMessage   = "invalid_message"
	ErrPairingExpired   = "pairing_expired"
	ErrChannelFull      = "channel_full"
	ErrChannelNotFound  = "channel_not_found"
	ErrNotInChannel     = "not_in_channel"
	ErrChallengeTimeout = "challenge_timeout"
	ErrVerifyRejected   = "verify_rejected"
	ErrReplaced         = "replaced"
	ErrRateLimited      = "rate_limited"
	ErrInternal         = "internal_error"
)

// Connection represents a single WebSocket connection.
type Connection struct {
	Conn     *websocket.Conn
	ID       string
	IP       string // originating IP address
	Channels map[string]bool // channelIds this connection has joined
	mu       sync.Mutex
	bytesOut *atomic.Int64 // shared counter for bytes sent
}

// WaitingPeer stores a peer waiting for pairing match.
type WaitingPeer struct {
	Conn     *Connection
	ID       string // id from the pair message (not conn.ID)
	PubShare []byte
	Created  time.Time
}

// ChannelMember represents one peer in a channel.
type ChannelMember struct {
	Conn     *Connection // nil for remote peers
	ID       string      // peer's self-reported id
	Role     string      // "initiator" or "responder"
	Nonce    []byte      // challenge nonce
	Response []byte      // challenge response (MAC)
	Remote   bool        // true if peer is on another node
}

// Channel represents a 1:1 relay conduit.
type Channel struct {
	mu      sync.Mutex
	State   string
	WaitGen uint64 // incremented each time State enters WAIT_PEER
	Peers   [2]*ChannelMember
}

// InMsg is an incoming message from a client.
type InMsg struct {
	Type     string `json:"type"`
	Ch       string `json:"ch,omitempty"`
	ID       string `json:"id,omitempty"`
	PubShare string `json:"pubShare,omitempty"` // base64url
	Mac      string `json:"mac,omitempty"`      // base64url
	Data     string `json:"data,omitempty"`     // base64url
	Code     string `json:"code,omitempty"`
	Role     string `json:"role,omitempty"`
}

// OutMsg is an outgoing message to a client.
type OutMsg struct {
	Type      string `json:"type"`
	Ch        string `json:"ch,omitempty"`
	PubShare  string `json:"pubShare,omitempty"`
	ID        string `json:"id,omitempty"`
	Role      string `json:"role,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	PeerNonce string `json:"peerNonce,omitempty"`
	PeerMac   string `json:"peerMac,omitempty"`
	PeerID    string `json:"peerId,omitempty"`
	PeerRole  string `json:"peerRole,omitempty"`
	Data      string `json:"data,omitempty"`
	Code      string `json:"code,omitempty"`
	Message   string `json:"message,omitempty"`
}
