package latchrelay

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

var b64 = base64.RawURLEncoding

// ChannelState holds the state of a paired channel.
type ChannelState struct {
	ChannelID string
	EncKey    []byte
	Role      string // "initiator" or "responder"
	PeerID    string
	Active    bool
}

// inMsg is an incoming message from the server.
type inMsg struct {
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

// outMsg is an outgoing message to the server.
type outMsg struct {
	Type     string `json:"type"`
	Ch       string `json:"ch,omitempty"`
	ID       string `json:"id,omitempty"`
	PubShare string `json:"pubShare,omitempty"`
	Mac      string `json:"mac,omitempty"`
	Data     string `json:"data,omitempty"`
	Role     string `json:"role,omitempty"`
	Code     string `json:"code,omitempty"`
}

// LatchClient is a WebSocket client for the latch-relay server.
type LatchClient struct {
	ws        *websocket.Conn
	id        string
	mu        sync.Mutex
	channels  map[string]*ChannelState
	onMessage func(channelID string, peerID string, data []byte)

	inbox     chan inMsg
	closed    chan struct{}
	closeOnce sync.Once
}

// NewClient connects to a latch-relay server.
func NewClient(serverURL, id string) (*LatchClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ws, _, err := websocket.Dial(ctx, serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", serverURL, err)
	}
	ws.SetReadLimit(256 * 1024)

	c := &LatchClient{
		ws:       ws,
		id:       id,
		channels: make(map[string]*ChannelState),
		inbox:    make(chan inMsg, 64),
		closed:   make(chan struct{}),
	}

	go c.readLoop()
	return c, nil
}

// OnMessage sets the callback for incoming decrypted messages.
func (c *LatchClient) OnMessage(fn func(channelID string, peerID string, data []byte)) {
	c.mu.Lock()
	c.onMessage = fn
	c.mu.Unlock()
}

// Pair performs the full pairing flow using a pairing code.
// It tries the current time window first, then the previous window.
func (c *LatchClient) Pair(code string) (*ChannelState, error) {
	current, previous := DerivePairingKeysForWindows(code)
	cs, err := c.PairDirect(current.PairingID, current.W)
	if err != nil {
		cs, err = c.PairDirect(previous.PairingID, previous.W)
		if err != nil {
			return nil, fmt.Errorf("pairing failed (both windows): %w", err)
		}
	}
	return cs, nil
}

// PairDirect performs the full pairing flow with pre-derived pairingID and w scalar.
func (c *LatchClient) PairDirect(pairingID string, w *big.Int) (*ChannelState, error) {
	// Both peers blind with M (role is unknown until server assigns it).
	// Role assignment only affects the transcript ordering in SPAKE2 Finish().
	spake, err := NewSPAKE2("initiator", w)
	if err != nil {
		return nil, fmt.Errorf("spake2 init: %w", err)
	}

	// Send pair message
	if err := c.send(outMsg{
		Type:     "pair",
		Ch:       pairingID,
		ID:       c.id,
		PubShare: b64.EncodeToString(spake.PubShare()),
	}); err != nil {
		return nil, fmt.Errorf("send pair: %w", err)
	}

	// Wait for pair_matched
	msg, err := c.waitFor("pair_matched", pairingID, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("wait pair_matched: %w", err)
	}

	role := msg.Role
	peerID := msg.ID

	// Update SPAKE2 role for transcript computation.
	// The pubShare was already sent and computed with M blinding.
	// Role only affects TT and which blinding to remove from peer's share.
	spake.Role = role

	peerPubShare, err := b64.DecodeString(msg.PubShare)
	if err != nil {
		return nil, fmt.Errorf("decode peer pubShare: %w", err)
	}

	// Complete SPAKE2 - the Finish method handles role-dependent unblinding
	ke, err := spake.Finish(peerPubShare, pairingID, c.id, peerID)
	if err != nil {
		return nil, fmt.Errorf("spake2 finish: %w", err)
	}

	channelID, encKey := DeriveChannelKeys(ke, pairingID)

	// Join channel and complete challenge-response.
	// The server may re-challenge us when the second peer joins, so we loop
	// until we get verify_peer, responding to each challenge.
	if err := c.send(outMsg{
		Type: "join",
		Ch:   channelID,
		ID:   c.id,
	}); err != nil {
		return nil, fmt.Errorf("send join: %w", err)
	}

	// Complete the challenge-response flow. The server may send multiple
	// challenges (re-challenge when second peer joins). We debounce: after
	// receiving a challenge, wait briefly for another before responding,
	// to avoid sending a response for a stale nonce that could race with
	// the re-challenge on the server side.
	verifyMsg, err := c.challengeLoop(channelID, encKey, role)
	if err != nil {
		return nil, err
	}

	if verifyMsg.PeerID == c.id {
		c.send(outMsg{Type: "error", Code: "verify_rejected", Ch: channelID})
		return nil, fmt.Errorf("verify_peer contains own ID (possible reflection attack)")
	}

	peerNonce, err := b64.DecodeString(verifyMsg.PeerNonce)
	if err != nil {
		return nil, fmt.Errorf("decode peer nonce: %w", err)
	}
	peerMac, err := b64.DecodeString(verifyMsg.PeerMac)
	if err != nil {
		return nil, fmt.Errorf("decode peer mac: %w", err)
	}

	peerRole := verifyMsg.PeerRole
	if peerRole == "" {
		if role == "initiator" {
			peerRole = "responder"
		} else {
			peerRole = "initiator"
		}
	}

	if !VerifyChallengeMac(encKey, channelID, peerNonce, verifyMsg.PeerID, peerRole, peerMac) {
		c.send(outMsg{Type: "error", Code: "verify_rejected", Ch: channelID})
		return nil, fmt.Errorf("peer MAC verification failed")
	}

	cs := &ChannelState{
		ChannelID: channelID,
		EncKey:    encKey,
		Role:      role,
		PeerID:    verifyMsg.PeerID,
		Active:    true,
	}

	c.mu.Lock()
	c.channels[channelID] = cs
	c.mu.Unlock()

	return cs, nil
}

// Rejoin rejoins an existing channel after reconnection.
func (c *LatchClient) Rejoin(channelID string, encKey []byte, role string) error {
	if err := c.send(outMsg{
		Type: "join",
		Ch:   channelID,
		ID:   c.id,
	}); err != nil {
		return fmt.Errorf("send join: %w", err)
	}

	verifyMsg, err := c.challengeLoop(channelID, encKey, role)
	if err != nil {
		return err
	}

	if verifyMsg.PeerID == c.id {
		c.send(outMsg{Type: "error", Code: "verify_rejected", Ch: channelID})
		return fmt.Errorf("verify_peer contains own ID (possible reflection attack)")
	}

	peerNonce, err := b64.DecodeString(verifyMsg.PeerNonce)
	if err != nil {
		return fmt.Errorf("decode peer nonce: %w", err)
	}
	peerMac, err := b64.DecodeString(verifyMsg.PeerMac)
	if err != nil {
		return fmt.Errorf("decode peer mac: %w", err)
	}

	peerRole := verifyMsg.PeerRole
	if peerRole == "" {
		if role == "initiator" {
			peerRole = "responder"
		} else {
			peerRole = "initiator"
		}
	}

	if !VerifyChallengeMac(encKey, channelID, peerNonce, verifyMsg.PeerID, peerRole, peerMac) {
		c.send(outMsg{Type: "error", Code: "verify_rejected", Ch: channelID})
		return fmt.Errorf("peer MAC verification failed")
	}

	cs := &ChannelState{
		ChannelID: channelID,
		EncKey:    encKey,
		Role:      role,
		PeerID:    verifyMsg.PeerID,
		Active:    true,
	}

	c.mu.Lock()
	c.channels[channelID] = cs
	c.mu.Unlock()

	return nil
}

// Send encrypts and sends a message on the given channel.
func (c *LatchClient) Send(channelID string, data []byte) error {
	c.mu.Lock()
	cs, ok := c.channels[channelID]
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("channel %s not found", channelID)
	}
	if !cs.Active {
		return fmt.Errorf("channel %s not active", channelID)
	}

	encrypted, err := Encrypt(cs.EncKey, data, channelID)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	return c.send(outMsg{
		Type: "message",
		Ch:   channelID,
		Data: b64.EncodeToString(encrypted),
	})
}

// Close closes the WebSocket connection.
func (c *LatchClient) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

// ID returns the client's ID.
func (c *LatchClient) ID() string {
	return c.id
}

// Channels returns a copy of the current channel states.
func (c *LatchClient) Channels() map[string]*ChannelState {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]*ChannelState, len(c.channels))
	for k, v := range c.channels {
		cp := *v
		out[k] = &cp
	}
	return out
}

func (c *LatchClient) send(msg outMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, data)
}

func (c *LatchClient) readLoop() {
	for {
		_, data, err := c.ws.Read(context.Background())
		if err != nil {
			select {
			case <-c.closed:
			default:
				log.Printf("latchrelay: read error: %v", err)
			}
			c.closeOnce.Do(func() {
				close(c.closed)
			})
			return
		}

		var msg inMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		if msg.Type == "message" {
			c.handleMessage(msg)
			continue
		}
		if msg.Type == "peer_left" {
			c.handlePeerLeft(msg)
			continue
		}

		// Auto-respond to challenges for established channels (reconnection scenario).
		// When a peer rejoins, the server re-challenges the existing peer.
		if msg.Type == "challenge" && c.autoRespondChallenge(msg) {
			continue
		}
		// Auto-handle verify_peer for established channels.
		if msg.Type == "verify_peer" && c.autoHandleVerifyPeer(msg) {
			continue
		}

		select {
		case c.inbox <- msg:
		default:
			log.Printf("latchrelay: inbox full, dropping %s message", msg.Type)
		}
	}
}

func (c *LatchClient) handleMessage(msg inMsg) {
	c.mu.Lock()
	cs, ok := c.channels[msg.Ch]
	cb := c.onMessage
	c.mu.Unlock()

	if !ok || cb == nil {
		return
	}

	data, err := b64.DecodeString(msg.Data)
	if err != nil {
		log.Printf("latchrelay: decode message data: %v", err)
		return
	}

	plaintext, err := Decrypt(cs.EncKey, data, msg.Ch)
	if err != nil {
		log.Printf("latchrelay: decrypt message: %v", err)
		return
	}

	cb(msg.Ch, msg.PeerID, plaintext)
}

// autoRespondChallenge automatically responds to a challenge for an
// established channel. Returns true if handled (message should not go to inbox).
func (c *LatchClient) autoRespondChallenge(msg inMsg) bool {
	c.mu.Lock()
	cs, ok := c.channels[msg.Ch]
	c.mu.Unlock()

	if !ok {
		return false // not an established channel, let inbox handle it
	}

	nonce, err := b64.DecodeString(msg.Nonce)
	if err != nil {
		return false
	}

	mac := ComputeChallengeMac(cs.EncKey, cs.ChannelID, nonce, c.id, cs.Role)
	c.send(outMsg{
		Type: "response",
		Ch:   cs.ChannelID,
		Mac:  b64.EncodeToString(mac),
	})

	return true
}

// autoHandleVerifyPeer handles verify_peer for established channels.
func (c *LatchClient) autoHandleVerifyPeer(msg inMsg) bool {
	c.mu.Lock()
	cs, ok := c.channels[msg.Ch]
	c.mu.Unlock()

	if !ok {
		return false
	}

	if msg.PeerID == c.id {
		return true // consume but don't activate — own ID reflection
	}

	peerNonce, err := b64.DecodeString(msg.PeerNonce)
	if err != nil {
		return false
	}
	peerMac, err := b64.DecodeString(msg.PeerMac)
	if err != nil {
		return false
	}

	peerRole := msg.PeerRole
	if peerRole == "" {
		if cs.Role == "initiator" {
			peerRole = "responder"
		} else {
			peerRole = "initiator"
		}
	}

	if VerifyChallengeMac(cs.EncKey, cs.ChannelID, peerNonce, msg.PeerID, peerRole, peerMac) {
		c.mu.Lock()
		cs.PeerID = msg.PeerID
		cs.Active = true
		c.mu.Unlock()
	}

	return true
}

func (c *LatchClient) handlePeerLeft(msg inMsg) {
	c.mu.Lock()
	if cs, ok := c.channels[msg.Ch]; ok {
		cs.Active = false
	}
	c.mu.Unlock()
}

// challengeLoop handles the challenge-response-verify flow.
// It debounces challenges to avoid responding to a stale nonce.
func (c *LatchClient) challengeLoop(channelID string, encKey []byte, role string) (inMsg, error) {
	var latestNonce string

	for {
		msg, err := c.waitForAny([]string{"challenge", "verify_peer"}, channelID, 15*time.Second)
		if err != nil {
			return inMsg{}, fmt.Errorf("challenge loop: %w", err)
		}

		if msg.Type == "verify_peer" {
			// If we haven't responded to any challenge yet (edge case),
			// the verify_peer might be from a previous session. Return it anyway.
			return msg, nil
		}

		// Got a challenge. Save the nonce and debounce: check if another
		// challenge follows quickly (re-challenge from second peer joining).
		latestNonce = msg.Nonce
		latestNonce = c.debounceChallenge(channelID, latestNonce)

		// Respond to the latest challenge
		nonce, err := b64.DecodeString(latestNonce)
		if err != nil {
			return inMsg{}, fmt.Errorf("decode nonce: %w", err)
		}
		mac := ComputeChallengeMac(encKey, channelID, nonce, c.id, role)
		if err := c.send(outMsg{
			Type: "response",
			Ch:   channelID,
			Mac:  b64.EncodeToString(mac),
		}); err != nil {
			return inMsg{}, fmt.Errorf("send response: %w", err)
		}

		// Now wait for verify_peer (or another re-challenge)
		for {
			msg2, err := c.waitForAny([]string{"challenge", "verify_peer"}, channelID, 15*time.Second)
			if err != nil {
				return inMsg{}, fmt.Errorf("wait verify: %w", err)
			}
			if msg2.Type == "verify_peer" {
				return msg2, nil
			}
			// Another re-challenge: respond immediately (we're already past debounce)
			nonce2, err := b64.DecodeString(msg2.Nonce)
			if err != nil {
				return inMsg{}, fmt.Errorf("decode nonce: %w", err)
			}
			mac2 := ComputeChallengeMac(encKey, channelID, nonce2, c.id, role)
			if err := c.send(outMsg{
				Type: "response",
				Ch:   channelID,
				Mac:  b64.EncodeToString(mac2),
			}); err != nil {
				return inMsg{}, fmt.Errorf("send response: %w", err)
			}
		}
	}
}

// debounceChallenge waits briefly to see if another challenge arrives,
// returning the latest nonce. This prevents responding to a stale nonce
// that would race with a re-challenge on the server.
func (c *LatchClient) debounceChallenge(channelID, currentNonce string) string {
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()

	for {
		select {
		case msg := <-c.inbox:
			if msg.Type == "challenge" && msg.Ch == channelID {
				// Got a fresher challenge, use this one
				currentNonce = msg.Nonce
				timer.Reset(50 * time.Millisecond)
				continue
			}
			// Not a challenge for our channel - put it back
			// We can't put it back in a buffered channel easily,
			// so just respond to what we have if it's something else
			// Actually this is tricky. For now, if we get a non-challenge
			// message during debounce, just stop debouncing.
			// Push it back, but guard against blocking if client is closing.
			go func() {
				select {
				case c.inbox <- msg:
				case <-c.closed:
				}
			}()
			return currentNonce
		case <-timer.C:
			return currentNonce
		}
	}
}

func (c *LatchClient) waitForAny(msgTypes []string, ch string, timeout time.Duration) (inMsg, error) {
	typeSet := make(map[string]bool, len(msgTypes))
	for _, t := range msgTypes {
		typeSet[t] = true
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case msg := <-c.inbox:
			if msg.Type == "error" {
				return msg, fmt.Errorf("server error: %s: %s", msg.Code, msg.Message)
			}
			if typeSet[msg.Type] && (ch == "" || msg.Ch == ch) {
				return msg, nil
			}
		case <-timer.C:
			return inMsg{}, fmt.Errorf("timeout waiting for %v on %s", msgTypes, ch)
		case <-c.closed:
			return inMsg{}, fmt.Errorf("connection closed while waiting for %v", msgTypes)
		}
	}
}

func (c *LatchClient) waitFor(msgType, ch string, timeout time.Duration) (inMsg, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case msg := <-c.inbox:
			if msg.Type == "error" {
				return msg, fmt.Errorf("server error: %s: %s", msg.Code, msg.Message)
			}
			if msg.Type == msgType && (ch == "" || msg.Ch == ch) {
				return msg, nil
			}
		case <-timer.C:
			return inMsg{}, fmt.Errorf("timeout waiting for %s on %s", msgType, ch)
		case <-c.closed:
			return inMsg{}, fmt.Errorf("connection closed while waiting for %s", msgType)
		}
	}
}
