package relay

// Lock ordering: Bridge.mu > Channel.mu > Connection.mu (per-instance).
// Never acquire a higher-level lock while holding a lower-level lock.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

var b64 = base64.RawURLEncoding

const (
	maxChLen = 128 // max length of Ch/ID fields
	maxIDLen = 64
)

// BridgeConfig holds all configurable parameters.
type BridgeConfig struct {
	MaxChannelsTotal  int
	MaxMessageSize    int64
	PairingTTL        time.Duration
	IdleTimeout       time.Duration
	ChallengeTimeout  time.Duration
	WaitPeerTimeout   time.Duration
	MaxPairingsPerIP  int // 0 = default (60)
	MaxChannelsPerIP  int // 0 = default (30)
	Debug             bool
	Backend           Backend // nil = auto-create MemoryBackend
}

// Bridge is the central relay server state.
type Bridge struct {
	mu          sync.Mutex
	channels    map[string]*Channel  // channelId -> Channel
	connections map[*Connection]bool // all active connections
	backend     Backend              // pairing storage + cross-node messaging
	cfg         BridgeConfig
	connRate    *RateLimiter // per-IP connection rate
	joinRate    *RateLimiter // per-channelId join rate
	pairRate    *RateLimiter // per-IP pairing rate
	channelRate *RateLimiter // per-IP channel rate
	stop        chan struct{}
	startTime   time.Time

	// Cumulative counters (atomic)
	BytesIn           atomic.Int64
	BytesOut          atomic.Int64
	MessagesRelayed   atomic.Int64
	PairingsCompleted atomic.Int64
	TotalConnections  atomic.Int64
}

// Stats holds a snapshot of server metrics.
type Stats struct {
	Uptime            string `json:"uptime"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
	Connections       int    `json:"connections"`
	Channels          int    `json:"channels"`
	ChannelsWaiting   int    `json:"channels_waiting"`
	ChannelsChallenging int  `json:"channels_challenging"`
	ChannelsActive    int    `json:"channels_active"`
	WaitingPairings   int    `json:"waiting_pairings"`
	MessagesRelayed   int64  `json:"messages_relayed"`
	PairingsCompleted int64  `json:"pairings_completed"`
	TotalConnections  int64  `json:"total_connections"`
	BytesIn           int64  `json:"bytes_in"`
	BytesOut          int64  `json:"bytes_out"`
}

// Stats returns a snapshot of current server metrics.
func (b *Bridge) Stats() Stats {
	b.mu.Lock()
	conns := len(b.connections)
	chTotal := len(b.channels)
	// Snapshot channel pointers under b.mu, then release before locking
	// individual channels to avoid AB-BA deadlock with removePeerFromChannelLocked.
	channels := make([]*Channel, 0, chTotal)
	for _, ch := range b.channels {
		channels = append(channels, ch)
	}
	b.mu.Unlock()

	var chWaiting, chChallenging, chActive int
	for _, ch := range channels {
		ch.mu.Lock()
		switch ch.State {
		case StateWaitPeer:
			chWaiting++
		case StateChallenging:
			chChallenging++
		case StateActive:
			chActive++
		}
		ch.mu.Unlock()
	}

	uptime := time.Since(b.startTime)
	return Stats{
		Uptime:            uptime.Truncate(time.Second).String(),
		UptimeSeconds:     int64(uptime.Seconds()),
		Connections:       conns,
		Channels:          chTotal,
		ChannelsWaiting:   chWaiting,
		ChannelsChallenging: chChallenging,
		ChannelsActive:    chActive,
		WaitingPairings:   b.backend.PairingCount(),
		MessagesRelayed:   b.MessagesRelayed.Load(),
		PairingsCompleted: b.PairingsCompleted.Load(),
		TotalConnections:  b.TotalConnections.Load(),
		BytesIn:           b.BytesIn.Load(),
		BytesOut:          b.BytesOut.Load(),
	}
}

func (b *Bridge) debugf(format string, args ...any) {
	if b.cfg.Debug {
		log.Printf("[DEBUG] "+format, args...)
	}
}

// NewBridge creates a new Bridge instance.
func NewBridge(cfg BridgeConfig) *Bridge {
	pairLimit := cfg.MaxPairingsPerIP
	if pairLimit <= 0 {
		pairLimit = 60
	}
	chanLimit := cfg.MaxChannelsPerIP
	if chanLimit <= 0 {
		chanLimit = 30
	}
	backend := cfg.Backend
	if backend == nil {
		backend = NewMemoryBackend()
	}
	b := &Bridge{
		channels:    make(map[string]*Channel),
		connections: make(map[*Connection]bool),
		backend:     backend,
		cfg:         cfg,
		connRate:     NewRateLimiter(10, time.Second),
		joinRate:     NewRateLimiter(3, 10*time.Second),
		pairRate:     NewRateLimiter(pairLimit, time.Minute),
		channelRate:  NewRateLimiter(chanLimit, time.Minute),
		stop:         make(chan struct{}),
		startTime:    time.Now(),
	}
	b.backend.Subscribe(b.handleRemoteMsg)
	go b.cleanupLoop()
	return b
}

// Close stops background goroutines and the backend.
func (b *Bridge) Close() {
	close(b.stop)
	b.backend.Close()
}

// cleanupLoop periodically removes expired waiting peers.
func (b *Bridge) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
		}

		expired := b.backend.CleanupPairings(b.cfg.PairingTTL)
		for _, e := range expired {
			sendMsg(e.Conn, OutMsg{Type: "error", Code: ErrPairingExpired, Ch: e.PairingID})
		}

		// Prune stale rate-limiter entries to prevent unbounded memory growth
		b.connRate.Cleanup()
		b.joinRate.Cleanup()
		b.pairRate.Cleanup()
		b.channelRate.Cleanup()
	}
}

// RegisterConn adds a connection to the bridge.
func (b *Bridge) RegisterConn(conn *Connection) {
	b.mu.Lock()
	b.connections[conn] = true
	b.mu.Unlock()
	b.TotalConnections.Add(1)
	b.debugf("conn+ ip=%s", conn.IP)
}

// UnregisterConn removes a connection and cleans up all its state.
func (b *Bridge) UnregisterConn(conn *Connection) {
	b.debugf("conn- ip=%s id=%s", conn.IP, conn.ID)
	// Collect channel IDs under conn.mu first, then release it before
	// acquiring higher-level locks. This preserves the documented lock
	// ordering: Bridge.mu > Channel.mu > Connection.mu.
	conn.mu.Lock()
	channelsCopy := make(map[string]bool, len(conn.Channels))
	for ch := range conn.Channels {
		channelsCopy[ch] = true
	}
	conn.mu.Unlock()

	// Remove from waiting peers (backend handles its own locking)
	b.backend.RemovePairingsByConn(conn)

	b.mu.Lock()

	// Remove from channels
	for chID := range channelsCopy {
		ch, ok := b.channels[chID]
		if !ok {
			continue
		}
		ch.mu.Lock()
		b.removePeerFromChannelLocked(ch, chID, conn, true)
		ch.mu.Unlock()
	}

	delete(b.connections, conn)
	b.mu.Unlock()
}

// HandleMessage dispatches an incoming message.
func (b *Bridge) HandleMessage(conn *Connection, msg InMsg) {
	switch msg.Type {
	case "pair":
		b.handlePair(conn, msg)
	case "join":
		b.handleJoin(conn, msg)
	case "response":
		b.handleResponse(conn, msg)
	case "message":
		b.handleRelay(conn, msg)
	case "leave":
		b.handleLeave(conn, msg)
	case "error":
		if msg.Code == ErrVerifyRejected {
			b.handleVerifyRejected(conn, msg)
		}
	default:
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "unknown message type"})
	}
}

func (b *Bridge) handlePair(conn *Connection, msg InMsg) {
	if msg.Ch == "" || msg.PubShare == "" || msg.ID == "" {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "pair requires ch, pubShare, id"})
		return
	}
	if len(msg.Ch) > maxChLen || len(msg.ID) > maxIDLen {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "field too long"})
		return
	}

	pubShareBytes, err := b64.DecodeString(msg.PubShare)
	if err != nil {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "invalid pubShare encoding"})
		return
	}

	if !b.pairRate.Allow(conn.IP) {
		b.debugf("rate_limited type=pair ip=%s", conn.IP)
		sendMsg(conn, OutMsg{Type: "error", Code: ErrRateLimited, Ch: msg.Ch, Message: "pairing rate exceeded"})
		return
	}

	match, err := b.backend.StorePairing(msg.Ch, PairingInfo{
		Conn:     conn,
		ID:       msg.ID,
		PubShare: pubShareBytes,
	})
	if err != nil {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInternal, Ch: msg.Ch, Message: "pairing error"})
		return
	}

	if match == nil {
		// First peer: waiting
		b.debugf("pair wait ch=%s id=%s ip=%s", msg.Ch[:min(16, len(msg.Ch))], msg.ID, conn.IP)
		return
	}

	// Matched
	b.PairingsCompleted.Add(1)
	b.debugf("pair matched ch=%s initiator=%s responder=%s", msg.Ch[:min(16, len(msg.Ch))], match.Initiator.ID, match.Responder.ID)

	if match.Initiator.Conn != nil {
		// Local match: both peers on this node
		sendMsg(match.Initiator.Conn, OutMsg{
			Type:     "pair_matched",
			Ch:       msg.Ch,
			PubShare: b64.EncodeToString(match.Responder.PubShare),
			ID:       match.Responder.ID,
			Role:     "initiator",
		})
	} else {
		// Cross-node: initiator is on another node, notify via pub/sub
		data, err := marshalRemoteMsg("pair_matched", msg.Ch, b.backend.NodeID(), RemotePairMatched{
			PeerID:       match.Responder.ID,
			PeerPubShare: match.Responder.PubShare,
		})
		if err == nil {
			if pubErr := b.backend.Publish(msg.Ch, data); pubErr != nil {
				log.Printf("publish pair_matched: %v", pubErr)
			}
		}
	}

	sendMsg(conn, OutMsg{
		Type:     "pair_matched",
		Ch:       msg.Ch,
		PubShare: b64.EncodeToString(match.Initiator.PubShare),
		ID:       match.Initiator.ID,
		Role:     "responder",
	})
}

func (b *Bridge) handleJoin(conn *Connection, msg InMsg) {
	b.debugf("join ch=%s id=%s ip=%s", msg.Ch[:min(16, len(msg.Ch))], msg.ID, conn.IP)
	if msg.Ch == "" || msg.ID == "" {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "join requires ch, id"})
		return
	}
	if len(msg.Ch) > maxChLen || len(msg.ID) > maxIDLen {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "field too long"})
		return
	}

	if !b.joinRate.Allow(msg.Ch) {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrRateLimited, Ch: msg.Ch, Message: "join rate exceeded"})
		return
	}

	if !b.channelRate.Allow(conn.IP) {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrRateLimited, Ch: msg.Ch, Message: "channel rate exceeded"})
		return
	}

	b.mu.Lock()

	ch, exists := b.channels[msg.Ch]
	if !exists {
		if len(b.channels) >= b.cfg.MaxChannelsTotal {
			b.mu.Unlock()
			sendMsg(conn, OutMsg{Type: "error", Code: ErrChannelFull, Ch: msg.Ch, Message: "max channels reached"})
			return
		}
		ch = &Channel{State: StateWaitPeer}
		b.channels[msg.Ch] = ch
	}

	// Hold b.mu while acquiring ch.mu to prevent TOCTOU with timeout goroutines
	ch.mu.Lock()
	b.mu.Unlock()
	defer ch.mu.Unlock()

	// Check for connection replacement
	for i, peer := range ch.Peers {
		if peer != nil && peer.ID == msg.ID {
			sendMsg(peer.Conn, OutMsg{Type: "error", Code: ErrReplaced, Ch: msg.Ch})
			peer.Conn.mu.Lock()
			delete(peer.Conn.Channels, msg.Ch)
			peer.Conn.mu.Unlock()
			ch.Peers[i] = nil
		}
	}

	// Find a free slot
	slot := -1
	peerCount := 0
	for i, peer := range ch.Peers {
		if peer != nil {
			peerCount++
		} else if slot == -1 {
			slot = i
		}
	}

	if slot == -1 {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrChannelFull, Ch: msg.Ch})
		return
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("failed to generate nonce: %v", err)
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInternal, Ch: msg.Ch, Message: "internal error"})
		return
	}

	member := &ChannelMember{
		Conn:  conn,
		ID:    msg.ID,
		Role:  msg.Role,
		Nonce: nonce,
	}
	ch.Peers[slot] = member

	conn.mu.Lock()
	conn.Channels[msg.Ch] = true
	conn.mu.Unlock()

	if peerCount == 0 {
		ch.State = StateWaitPeer
		ch.WaitGen++
		gen := ch.WaitGen
		sendMsg(conn, OutMsg{Type: "challenge", Ch: msg.Ch, Nonce: b64.EncodeToString(nonce)})
		go b.waitPeerTimeout(msg.Ch, gen)
	} else {
		// Second peer: re-challenge BOTH with fresh nonces
		ch.State = StateChallenging

		for i, peer := range ch.Peers {
			if peer != nil && peer != member {
				freshNonce := make([]byte, 32)
				if _, err := rand.Read(freshNonce); err != nil {
					log.Printf("failed to generate nonce: %v", err)
					sendMsg(conn, OutMsg{Type: "error", Code: ErrInternal, Ch: msg.Ch, Message: "internal error"})
					ch.Peers[slot] = nil
					conn.mu.Lock()
					delete(conn.Channels, msg.Ch)
					conn.mu.Unlock()
					ch.State = StateWaitPeer
					ch.WaitGen++
					go b.waitPeerTimeout(msg.Ch, ch.WaitGen)
					return
				}
				ch.Peers[i].Nonce = freshNonce
				ch.Peers[i].Response = nil
				if peer.Remote {
					// Notify remote node to re-challenge its peer
					data, err := marshalRemoteMsg("join_notify", msg.Ch, b.backend.NodeID(), RemoteJoinNotify{
						PeerID: msg.ID,
						Nonce:  nonce,
					})
					if err == nil {
						if pubErr := b.backend.Publish(msg.Ch, data); pubErr != nil {
							log.Printf("publish join_notify: %v", pubErr)
						}
					}
				} else {
					sendMsg(peer.Conn, OutMsg{Type: "challenge", Ch: msg.Ch, Nonce: b64.EncodeToString(freshNonce)})
				}
			}
		}

		sendMsg(conn, OutMsg{Type: "challenge", Ch: msg.Ch, Nonce: b64.EncodeToString(nonce)})
	}

	go b.challengeTimeout(msg.Ch, conn)
}

func (b *Bridge) handleResponse(conn *Connection, msg InMsg) {
	if msg.Ch == "" || msg.Mac == "" {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "response requires ch, mac"})
		return
	}

	macBytes, err := b64.DecodeString(msg.Mac)
	if err != nil {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "invalid mac encoding"})
		return
	}

	b.mu.Lock()
	ch, exists := b.channels[msg.Ch]
	if exists {
		ch.mu.Lock()
	}
	b.mu.Unlock()

	if !exists {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrChannelNotFound, Ch: msg.Ch})
		return
	}
	defer ch.mu.Unlock()

	// Find the responding peer
	peerIdx := -1
	for i, peer := range ch.Peers {
		if peer != nil && peer.Conn == conn {
			peerIdx = i
			break
		}
	}

	if peerIdx == -1 {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrNotInChannel, Ch: msg.Ch})
		return
	}

	ch.Peers[peerIdx].Response = macBytes
	if msg.Role != "" {
		ch.Peers[peerIdx].Role = msg.Role
	}

	// If the other peer is remote, forward our response via pub/sub
	otherIdx := 1 - peerIdx
	if ch.Peers[otherIdx] != nil && ch.Peers[otherIdx].Remote {
		data, err := marshalRemoteMsg("response", msg.Ch, b.backend.NodeID(), RemoteResponse{
			PeerID:   ch.Peers[peerIdx].ID,
			Role:     ch.Peers[peerIdx].Role,
			Nonce:    ch.Peers[peerIdx].Nonce,
			Response: macBytes,
		})
		if err == nil {
			if pubErr := b.backend.Publish(msg.Ch, data); pubErr != nil {
				log.Printf("publish response: %v", pubErr)
			}
		}
	}

	// Check if both peers have responded
	if ch.Peers[0] == nil || ch.Peers[1] == nil {
		return
	}
	if ch.Peers[0].Response == nil || ch.Peers[1].Response == nil {
		return
	}

	// Both responded: send verify_peer to each
	b.debugf("verified ch=%s peer0=%s peer1=%s", msg.Ch[:min(16, len(msg.Ch))], ch.Peers[0].ID, ch.Peers[1].ID)
	for i := 0; i < 2; i++ {
		other := 1 - i
		outMsg := OutMsg{
			Type:      "verify_peer",
			Ch:        msg.Ch,
			PeerNonce: b64.EncodeToString(ch.Peers[other].Nonce),
			PeerMac:   b64.EncodeToString(ch.Peers[other].Response),
			PeerID:    ch.Peers[other].ID,
			PeerRole:  ch.Peers[other].Role,
		}
		if ch.Peers[i].Remote {
			// Remote peer's node handles its own verify_peer delivery
			continue
		}
		sendMsg(ch.Peers[i].Conn, outMsg)
	}

	ch.State = StateActive

	// Clear transient challenge data per spec
	for _, peer := range ch.Peers {
		if peer != nil {
			peer.Nonce = nil
			peer.Response = nil
		}
	}
}

func (b *Bridge) handleRelay(conn *Connection, msg InMsg) {
	if msg.Ch == "" || msg.Data == "" {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "message requires ch, data"})
		return
	}

	b.mu.Lock()
	ch, exists := b.channels[msg.Ch]
	if exists {
		ch.mu.Lock()
	}
	b.mu.Unlock()

	if !exists {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrChannelNotFound, Ch: msg.Ch})
		return
	}
	defer ch.mu.Unlock()

	if ch.State != StateActive {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrNotInChannel, Ch: msg.Ch})
		return
	}

	senderIdx := -1
	for i, peer := range ch.Peers {
		if peer != nil && peer.Conn == conn {
			senderIdx = i
			break
		}
	}
	if senderIdx == -1 {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrNotInChannel, Ch: msg.Ch})
		return
	}

	otherIdx := 1 - senderIdx
	if ch.Peers[otherIdx] == nil {
		return // fire-and-forget
	}

	b.MessagesRelayed.Add(1)
	b.debugf("relay ch=%s from=%s to=%s bytes=%d", msg.Ch[:min(16, len(msg.Ch))], ch.Peers[senderIdx].ID, ch.Peers[otherIdx].ID, len(msg.Data))

	if ch.Peers[otherIdx].Remote {
		// Cross-node: forward via pub/sub
		data, err := marshalRemoteMsg("relay", msg.Ch, b.backend.NodeID(), RemoteRelay{
			PeerID: ch.Peers[senderIdx].ID,
			Data:   msg.Data,
		})
		if err == nil {
			if pubErr := b.backend.Publish(msg.Ch, data); pubErr != nil {
				log.Printf("publish relay: %v", pubErr)
			}
		}
	} else {
		sendMsg(ch.Peers[otherIdx].Conn, OutMsg{
			Type:   "message",
			Ch:     msg.Ch,
			PeerID: ch.Peers[senderIdx].ID,
			Data:   msg.Data,
		})
	}
}

func (b *Bridge) handleLeave(conn *Connection, msg InMsg) {
	b.debugf("leave ch=%s id=%s", msg.Ch[:min(16, len(msg.Ch))], conn.ID)
	if msg.Ch == "" {
		sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "leave requires ch"})
		return
	}

	b.mu.Lock()
	ch, exists := b.channels[msg.Ch]
	if !exists {
		b.mu.Unlock()
		return
	}
	ch.mu.Lock()
	b.mu.Unlock()

	empty := b.removePeerFromChannelLocked(ch, msg.Ch, conn, false)
	ch.mu.Unlock()

	if empty {
		b.mu.Lock()
		if b.channels[msg.Ch] == ch {
			delete(b.channels, msg.Ch)
		}
		b.mu.Unlock()
	}

	conn.mu.Lock()
	delete(conn.Channels, msg.Ch)
	conn.mu.Unlock()
}

func (b *Bridge) handleVerifyRejected(conn *Connection, msg InMsg) {
	if msg.Ch == "" {
		return
	}

	b.mu.Lock()
	ch, exists := b.channels[msg.Ch]
	if !exists {
		b.mu.Unlock()
		return
	}

	// Hold b.mu, acquire ch.mu, then delete channel — consistent lock ordering
	ch.mu.Lock()

	// Collect peers to notify after releasing locks
	var toNotify *Connection

	for _, peer := range ch.Peers {
		if peer != nil && peer.Conn != conn {
			toNotify = peer.Conn
			peer.Conn.mu.Lock()
			delete(peer.Conn.Channels, msg.Ch)
			peer.Conn.mu.Unlock()
		}
		if peer != nil && peer.Conn == conn {
			conn.mu.Lock()
			delete(conn.Channels, msg.Ch)
			conn.mu.Unlock()
		}
	}

	delete(b.channels, msg.Ch)
	ch.mu.Unlock()
	b.mu.Unlock()

	if toNotify != nil {
		sendMsg(toNotify, OutMsg{Type: "error", Code: ErrVerifyRejected, Ch: msg.Ch})
	}
}

// removePeerFromChannelLocked removes a peer from a channel.
// ch.mu must be held. If holdingBridgeMu is true, the caller already holds b.mu.
// Returns true if the channel is now empty and should be deleted from b.channels.
// When holdingBridgeMu is true, the deletion is done inline.
// When holdingBridgeMu is false, the caller must delete after releasing ch.mu.
func (b *Bridge) removePeerFromChannelLocked(ch *Channel, chID string, conn *Connection, holdingBridgeMu bool) (empty bool) {
	removedIdx := -1
	removedID := ""
	for i, peer := range ch.Peers {
		if peer != nil && peer.Conn == conn {
			removedIdx = i
			removedID = peer.ID
			ch.Peers[i] = nil
			break
		}
	}

	if removedIdx == -1 {
		return false
	}

	var remaining *ChannelMember
	for _, peer := range ch.Peers {
		if peer != nil {
			remaining = peer
		}
	}

	if remaining == nil {
		if holdingBridgeMu {
			delete(b.channels, chID)
		}
		return !holdingBridgeMu // caller must delete if we didn't
	}

	// Other peer remains: transition to WAIT_PEER, clear challenge data
	ch.State = StateWaitPeer
	ch.WaitGen++
	gen := ch.WaitGen
	remaining.Nonce = nil
	remaining.Response = nil

	if remaining.Remote {
		// Notify remote node
		data, err := marshalRemoteMsg("peer_left", chID, b.backend.NodeID(), RemotePeerLeft{PeerID: removedID})
		if err == nil {
			if pubErr := b.backend.Publish(chID, data); pubErr != nil {
				log.Printf("publish peer_left: %v", pubErr)
			}
		}
	} else {
		sendMsg(remaining.Conn, OutMsg{Type: "peer_left", Ch: chID, PeerID: removedID})
	}

	go b.waitPeerTimeout(chID, gen)
	return false
}

func (b *Bridge) challengeTimeout(chID string, conn *Connection) {
	timer := time.NewTimer(b.cfg.ChallengeTimeout)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-b.stop:
		return
	}

	b.mu.Lock()
	ch, exists := b.channels[chID]
	if !exists {
		b.mu.Unlock()
		return
	}
	ch.mu.Lock()
	b.mu.Unlock()

	shouldDelete := false
	for i, peer := range ch.Peers {
		if peer != nil && peer.Conn == conn && peer.Response == nil {
			b.debugf("challenge_timeout ch=%s id=%s", chID[:min(16, len(chID))], peer.ID)
			sendMsg(conn, OutMsg{Type: "error", Code: ErrChallengeTimeout, Ch: chID})
			ch.Peers[i] = nil
			conn.mu.Lock()
			delete(conn.Channels, chID)
			conn.mu.Unlock()

			var remaining *ChannelMember
			for _, p := range ch.Peers {
				if p != nil {
					remaining = p
				}
			}
			if remaining == nil {
				shouldDelete = true
			} else {
				ch.State = StateWaitPeer
				remaining.Nonce = nil
				remaining.Response = nil
			}
			break
		}
	}
	ch.mu.Unlock()

	if shouldDelete {
		b.mu.Lock()
		if b.channels[chID] == ch {
			delete(b.channels, chID)
		}
		b.mu.Unlock()
	}
}

func (b *Bridge) waitPeerTimeout(chID string, gen uint64) {
	timer := time.NewTimer(b.cfg.WaitPeerTimeout)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-b.stop:
		return
	}

	b.mu.Lock()
	ch, exists := b.channels[chID]
	if !exists {
		b.mu.Unlock()
		return
	}
	ch.mu.Lock()
	b.mu.Unlock()

	shouldDelete := false
	if ch.State == StateWaitPeer && ch.WaitGen == gen {
		for i, peer := range ch.Peers {
			if peer == nil {
				continue
			}
			if peer.Remote || peer.Conn == nil {
				ch.Peers[i] = nil
				continue
			}
			sendMsg(peer.Conn, OutMsg{Type: "error", Code: ErrChallengeTimeout, Ch: chID})
			peer.Conn.mu.Lock()
			delete(peer.Conn.Channels, chID)
			peer.Conn.mu.Unlock()
			ch.Peers[i] = nil
		}
		shouldDelete = true
	}
	ch.mu.Unlock()

	if shouldDelete {
		b.mu.Lock()
		if b.channels[chID] == ch {
			delete(b.channels, chID)
		}
		b.mu.Unlock()
	}
}

// sendMsg writes a JSON message to a connection. Fire-and-forget.
func sendMsg(conn *Connection, msg OutMsg) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := marshalJSON(msg)
	if err != nil {
		return
	}
	if err := conn.Conn.Write(ctx, websocket.MessageText, data); err == nil && conn.bytesOut != nil {
		conn.bytesOut.Add(int64(len(data)))
	}
}

// handleRemoteMsg dispatches messages received from other nodes via pub/sub.
func (b *Bridge) handleRemoteMsg(channelId string, msg []byte) {
	var env RemoteMsg
	if err := json.Unmarshal(msg, &env); err != nil {
		return
	}

	// Skip messages from self (echo prevention)
	if env.NodeID != "" && env.NodeID == b.backend.NodeID() {
		return
	}

	switch env.Type {
	case "pair_matched":
		var pm RemotePairMatched
		if err := json.Unmarshal(env.Data, &pm); err != nil {
			return
		}
		b.handleRemotePairMatched(env.Ch, pm)

	case "relay":
		var rm RemoteRelay
		if err := json.Unmarshal(env.Data, &rm); err != nil {
			return
		}
		b.handleRemoteRelay(env.Ch, rm)

	case "join_notify":
		var jn RemoteJoinNotify
		if err := json.Unmarshal(env.Data, &jn); err != nil {
			return
		}
		b.handleRemoteJoinNotify(env.Ch, jn)

	case "response":
		var rr RemoteResponse
		if err := json.Unmarshal(env.Data, &rr); err != nil {
			return
		}
		b.handleRemoteResponse(env.Ch, rr)

	case "peer_left":
		var pl RemotePeerLeft
		if err := json.Unmarshal(env.Data, &pl); err != nil {
			return
		}
		b.handleRemotePeerLeft(env.Ch, pl)
	}
}

// handleRemotePairMatched delivers pair_matched to a local waiting peer
// when the match was made on another node.
func (b *Bridge) handleRemotePairMatched(pairingId string, pm RemotePairMatched) {
	info := b.backend.PopLocalPairing(pairingId)
	if info == nil || info.Conn == nil {
		return
	}

	b.debugf("remote pair_matched ch=%s local_peer=%s remote_peer=%s", pairingId[:min(16, len(pairingId))], info.ID, pm.PeerID)

	sendMsg(info.Conn, OutMsg{
		Type:     "pair_matched",
		Ch:       pairingId,
		PubShare: b64.EncodeToString(pm.PeerPubShare),
		ID:       pm.PeerID,
		Role:     "initiator",
	})
}

// handleRemoteRelay delivers a relayed message from a remote peer to the local peer.
func (b *Bridge) handleRemoteRelay(channelId string, rm RemoteRelay) {
	b.mu.Lock()
	ch, exists := b.channels[channelId]
	if exists {
		ch.mu.Lock()
	}
	b.mu.Unlock()

	if !exists {
		return
	}
	defer ch.mu.Unlock()

	// Find the local peer to deliver to
	for _, peer := range ch.Peers {
		if peer != nil && !peer.Remote && peer.Conn != nil {
			sendMsg(peer.Conn, OutMsg{
				Type:   "message",
				Ch:     channelId,
				PeerID: rm.PeerID,
				Data:   rm.Data,
			})
			return
		}
	}
}

// handleRemoteJoinNotify handles a remote peer joining a channel.
// Creates a remote stub in the channel and re-challenges the local peer.
func (b *Bridge) handleRemoteJoinNotify(channelId string, jn RemoteJoinNotify) {
	b.mu.Lock()
	ch, exists := b.channels[channelId]
	if !exists {
		if len(b.channels) >= b.cfg.MaxChannelsTotal {
			b.mu.Unlock()
			return
		}
		ch = &Channel{State: StateWaitPeer}
		b.channels[channelId] = ch
	}
	ch.mu.Lock()
	b.mu.Unlock()
	defer ch.mu.Unlock()

	// Find a free slot for the remote peer
	slot := -1
	for i, peer := range ch.Peers {
		if peer != nil && peer.ID == jn.PeerID {
			// Already known, update
			ch.Peers[i].Nonce = jn.Nonce
			ch.Peers[i].Response = nil
			slot = -2 // signal: updated existing
			break
		}
		if peer == nil && slot == -1 {
			slot = i
		}
	}

	if slot >= 0 {
		ch.Peers[slot] = &ChannelMember{
			ID:     jn.PeerID,
			Nonce:  jn.Nonce,
			Remote: true,
		}
	}

	// Re-challenge the local peer with a fresh nonce
	ch.State = StateChallenging
	for i, peer := range ch.Peers {
		if peer != nil && !peer.Remote && peer.Conn != nil {
			freshNonce := make([]byte, 32)
			rand.Read(freshNonce)
			ch.Peers[i].Nonce = freshNonce
			ch.Peers[i].Response = nil
			sendMsg(peer.Conn, OutMsg{Type: "challenge", Ch: channelId, Nonce: b64.EncodeToString(freshNonce)})
		}
	}
}

// handleRemoteResponse handles a challenge response from a remote peer.
func (b *Bridge) handleRemoteResponse(channelId string, rr RemoteResponse) {
	b.mu.Lock()
	ch, exists := b.channels[channelId]
	if exists {
		ch.mu.Lock()
	}
	b.mu.Unlock()

	if !exists {
		return
	}
	defer ch.mu.Unlock()

	// Store the remote peer's response
	for _, peer := range ch.Peers {
		if peer != nil && peer.ID == rr.PeerID {
			peer.Response = rr.Response
			peer.Nonce = rr.Nonce
			if rr.Role != "" {
				peer.Role = rr.Role
			}
			break
		}
	}

	// Check if both peers have responded
	if ch.Peers[0] == nil || ch.Peers[1] == nil {
		return
	}
	if ch.Peers[0].Response == nil || ch.Peers[1].Response == nil {
		return
	}

	// Both responded: send verify_peer to local peer, publish for remote
	b.debugf("verified (cross-node) ch=%s peer0=%s peer1=%s", channelId[:min(16, len(channelId))], ch.Peers[0].ID, ch.Peers[1].ID)
	for i := 0; i < 2; i++ {
		other := 1 - i
		outMsg := OutMsg{
			Type:      "verify_peer",
			Ch:        channelId,
			PeerNonce: b64.EncodeToString(ch.Peers[other].Nonce),
			PeerMac:   b64.EncodeToString(ch.Peers[other].Response),
			PeerID:    ch.Peers[other].ID,
			PeerRole:  ch.Peers[other].Role,
		}
		if !ch.Peers[i].Remote {
			sendMsg(ch.Peers[i].Conn, outMsg)
		}
		// Remote peer's node handles verify_peer delivery from its own response flow
	}

	ch.State = StateActive
	for _, peer := range ch.Peers {
		if peer != nil {
			peer.Nonce = nil
			peer.Response = nil
		}
	}
}

// handleRemotePeerLeft handles notification that a remote peer left.
func (b *Bridge) handleRemotePeerLeft(channelId string, pl RemotePeerLeft) {
	b.mu.Lock()
	ch, exists := b.channels[channelId]
	if exists {
		ch.mu.Lock()
	}
	b.mu.Unlock()

	if !exists {
		return
	}
	defer ch.mu.Unlock()

	for i, peer := range ch.Peers {
		if peer != nil && peer.Remote && peer.ID == pl.PeerID {
			ch.Peers[i] = nil

			// Notify local peer
			for _, local := range ch.Peers {
				if local != nil && !local.Remote && local.Conn != nil {
					sendMsg(local.Conn, OutMsg{Type: "peer_left", Ch: channelId, PeerID: pl.PeerID})
				}
			}
			break
		}
	}
}
