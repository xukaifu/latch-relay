package relay

// Lock ordering: Bridge.mu > Channel.mu > Connection.mu (per-instance).
// Never acquire a higher-level lock while holding a lower-level lock.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	MaxPairingsPerIP  int // 0 = default (5)
	MaxChannelsPerIP  int // 0 = default (20)
	Debug             bool
}

// Bridge is the central relay server state.
type Bridge struct {
	mu           sync.Mutex
	waitingPeers map[string]*WaitingPeer // pairingId -> WaitingPeer
	channels     map[string]*Channel     // channelId -> Channel
	connections  map[*Connection]bool    // all active connections
	cfg          BridgeConfig
	connRate     *RateLimiter // per-IP connection rate
	joinRate     *RateLimiter // per-channelId join rate
	pairRate     *RateLimiter // per-IP pairing rate (MaxPairingsPerIP = 5)
	channelRate  *RateLimiter // per-IP channel rate (MaxChannelsPerIP = 20)
	stop         chan struct{}
	startTime    time.Time

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
	waiting := len(b.waitingPeers)
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
		WaitingPairings:   waiting,
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
		pairLimit = 20
	}
	chanLimit := cfg.MaxChannelsPerIP
	if chanLimit <= 0 {
		chanLimit = 10
	}
	b := &Bridge{
		waitingPeers: make(map[string]*WaitingPeer),
		channels:     make(map[string]*Channel),
		connections:  make(map[*Connection]bool),
		cfg:          cfg,
		connRate:     NewRateLimiter(10, time.Second),
		joinRate:     NewRateLimiter(3, 10*time.Second),
		pairRate:     NewRateLimiter(pairLimit, time.Minute),
		channelRate:  NewRateLimiter(chanLimit, time.Minute),
		stop:         make(chan struct{}),
		startTime:    time.Now(),
	}
	go b.cleanupLoop()
	return b
}

// Close stops background goroutines.
func (b *Bridge) Close() {
	close(b.stop)
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

		// Collect expired peers under lock, send messages after releasing
		var expired []struct {
			conn *Connection
			id   string
		}

		b.mu.Lock()
		now := time.Now()
		for id, wp := range b.waitingPeers {
			if now.Sub(wp.Created) > b.cfg.PairingTTL {
				expired = append(expired, struct {
					conn *Connection
					id   string
				}{wp.Conn, id})
				delete(b.waitingPeers, id)
			}
		}
		b.mu.Unlock()

		for _, e := range expired {
			sendMsg(e.conn, OutMsg{Type: "error", Code: ErrPairingExpired, Ch: e.id})
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

	b.mu.Lock()

	// Remove from waiting peers
	for id, wp := range b.waitingPeers {
		if wp.Conn == conn {
			delete(b.waitingPeers, id)
		}
	}

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

	b.mu.Lock()

	wp, exists := b.waitingPeers[msg.Ch]
	if !exists {
		// First peer: store as waiting
		b.debugf("pair wait ch=%s id=%s ip=%s", msg.Ch[:min(16, len(msg.Ch))], msg.ID, conn.IP)
		b.waitingPeers[msg.Ch] = &WaitingPeer{
			Conn:     conn,
			ID:       msg.ID,
			PubShare: pubShareBytes,
			Created:  time.Now(),
		}
		b.mu.Unlock()
		return
	}

	// Check if expired
	if time.Since(wp.Created) > b.cfg.PairingTTL {
		delete(b.waitingPeers, msg.Ch)
		b.mu.Unlock()
		sendMsg(conn, OutMsg{Type: "error", Code: ErrPairingExpired, Ch: msg.Ch})
		return
	}

	// Second peer: match — collect data under lock, send after release
	initiatorConn := wp.Conn
	initiatorPubShare := wp.PubShare
	initiatorID := wp.ID
	responderPubShare := pubShareBytes
	responderID := msg.ID

	delete(b.waitingPeers, msg.Ch)
	b.mu.Unlock()

	b.PairingsCompleted.Add(1)
	b.debugf("pair matched ch=%s initiator=%s responder=%s", msg.Ch[:min(16, len(msg.Ch))], initiatorID, responderID)

	sendMsg(initiatorConn, OutMsg{
		Type:     "pair_matched",
		Ch:       msg.Ch,
		PubShare: b64.EncodeToString(responderPubShare),
		ID:       responderID,
		Role:     "initiator",
	})

	sendMsg(conn, OutMsg{
		Type:     "pair_matched",
		Ch:       msg.Ch,
		PubShare: b64.EncodeToString(initiatorPubShare),
		ID:       initiatorID,
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
					// Remove the newly added peer and restore channel to WaitPeer
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
				sendMsg(peer.Conn, OutMsg{Type: "challenge", Ch: msg.Ch, Nonce: b64.EncodeToString(freshNonce)})
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
		sendMsg(ch.Peers[i].Conn, OutMsg{
			Type:      "verify_peer",
			Ch:        msg.Ch,
			PeerNonce: b64.EncodeToString(ch.Peers[other].Nonce),
			PeerMac:   b64.EncodeToString(ch.Peers[other].Response),
			PeerID:    ch.Peers[other].ID,
			PeerRole:  ch.Peers[other].Role,
		})
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

	sendMsg(ch.Peers[otherIdx].Conn, OutMsg{
		Type:   "message",
		Ch:     msg.Ch,
		PeerID: ch.Peers[senderIdx].ID,
		Data:   msg.Data,
	})
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

	b.removePeerFromChannelLocked(ch, msg.Ch, conn, false)
	ch.mu.Unlock()

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

// removePeerFromChannelLocked removes a peer from a channel. ch.mu must be held.
// If holdingBridgeMu is true, the caller already holds b.mu.
func (b *Bridge) removePeerFromChannelLocked(ch *Channel, chID string, conn *Connection, holdingBridgeMu bool) {
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
		return // silently skip (handles races)
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
		} else {
			b.mu.Lock()
			delete(b.channels, chID)
			b.mu.Unlock()
		}
		return
	}

	// Other peer remains: transition to WAIT_PEER, clear challenge data
	ch.State = StateWaitPeer
	ch.WaitGen++
	gen := ch.WaitGen
	remaining.Nonce = nil
	remaining.Response = nil

	sendMsg(remaining.Conn, OutMsg{Type: "peer_left", Ch: chID, PeerID: removedID})

	go b.waitPeerTimeout(chID, gen)
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
	defer ch.mu.Unlock()

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
				b.mu.Lock()
				delete(b.channels, chID)
				b.mu.Unlock()
			} else {
				ch.State = StateWaitPeer
				remaining.Nonce = nil
				remaining.Response = nil
			}
			return
		}
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
	defer ch.mu.Unlock()

	if ch.State != StateWaitPeer || ch.WaitGen != gen {
		return // stale timeout
	}

	for i, peer := range ch.Peers {
		if peer != nil {
			sendMsg(peer.Conn, OutMsg{Type: "error", Code: ErrChallengeTimeout, Ch: chID})
			peer.Conn.mu.Lock()
			delete(peer.Conn.Channels, chID)
			peer.Conn.mu.Unlock()
			ch.Peers[i] = nil
		}
	}

	b.mu.Lock()
	delete(b.channels, chID)
	b.mu.Unlock()
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
