package relay

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"nhooyr.io/websocket"
)

// marshalJSON encodes an OutMsg to JSON bytes.
func marshalJSON(msg OutMsg) ([]byte, error) {
	return json.Marshal(msg)
}

// clientIP extracts the client IP. When trustProxy is true, it reads
// X-Forwarded-For / X-Real-IP headers; otherwise it uses RemoteAddr only.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i != -1 {
				xff = xff[:i]
			}
			if ip := strings.TrimSpace(xff); ip != "" {
				return ip
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

// HandleConnect returns an HTTP handler that upgrades to WebSocket and runs the relay.
func HandleConnect(b *Bridge, idleTimeout time.Duration, maxMsgSize int64, trustProxy bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, trustProxy)
		if !b.connRate.Allow(ip) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}

		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true, // allow any origin
		})
		if err != nil {
			log.Printf("websocket accept error: %v", err)
			return
		}
		ws.SetReadLimit(maxMsgSize)

		conn := &Connection{
			Conn:     ws,
			IP:       ip,
			Channels: make(map[string]bool),
			bytesOut: &b.BytesOut,
		}
		b.RegisterConn(conn)
		defer b.UnregisterConn(conn)
		defer ws.Close(websocket.StatusNormalClosure, "")

		for {
			ctx, cancel := context.WithTimeout(context.Background(), idleTimeout)
			typ, data, err := ws.Read(ctx)
			cancel()
			if err != nil {
				return
			}
			if typ != websocket.MessageText {
				continue
			}
			b.BytesIn.Add(int64(len(data)))

			var msg InMsg
			if err := json.Unmarshal(data, &msg); err != nil {
				sendMsg(conn, OutMsg{Type: "error", Code: ErrInvalidMessage, Message: "malformed JSON"})
				continue
			}

			// Set connection ID from first message that has one
			if msg.ID != "" && conn.ID == "" {
				conn.ID = msg.ID
			}

			b.HandleMessage(conn, msg)
		}
	}
}
