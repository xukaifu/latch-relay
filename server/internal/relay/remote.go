package relay

import "encoding/json"

// RemoteMsg is the envelope for cross-node messages via pub/sub.
type RemoteMsg struct {
	Type   string          `json:"type"`
	Ch     string          `json:"ch"`
	NodeID string          `json:"nodeId"` // sender node, used to skip self-echo
	Data   json.RawMessage `json:"data,omitempty"`
}

// Remote message types exchanged between nodes via pub/sub.

// RemotePairMatched notifies a node that its waiting peer was matched.
type RemotePairMatched struct {
	PeerID       string `json:"peerId"`
	PeerPubShare []byte `json:"peerPubShare"`
}

// RemoteJoinNotify tells the other node that a peer joined a channel.
type RemoteJoinNotify struct {
	PeerID string `json:"peerId"`
	Nonce  []byte `json:"nonce"`
}

// RemoteResponse forwards a challenge response from a remote peer.
type RemoteResponse struct {
	PeerID   string `json:"peerId"`
	Role     string `json:"role"`
	Nonce    []byte `json:"nonce"`
	Response []byte `json:"response"`
}

// RemoteRelay forwards an encrypted message to a remote peer.
type RemoteRelay struct {
	PeerID string `json:"peerId"`
	Data   string `json:"data"` // base64url
}

// RemotePeerLeft notifies the other node that a peer left.
type RemotePeerLeft struct {
	PeerID string `json:"peerId"`
}

func marshalRemoteMsg(msgType, ch, nodeID string, data any) ([]byte, error) {
	d, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return json.Marshal(RemoteMsg{Type: msgType, Ch: ch, NodeID: nodeID, Data: d})
}
