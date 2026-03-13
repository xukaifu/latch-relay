package main

import (
	"log"
	"net/http"

	"github.com/xukaifu/latch-relay/server/internal/relay"
)

func main() {
	cfg := LoadConfig()
	b := relay.NewBridge(relay.BridgeConfig{
		MaxChannelsTotal: cfg.MaxChannelsTotal,
		MaxMessageSize:   cfg.MaxMessageSize,
		PairingTTL:       cfg.PairingTTL,
		IdleTimeout:      cfg.IdleTimeout,
		ChallengeTimeout: cfg.ChallengeTimeout,
		WaitPeerTimeout:  cfg.WaitPeerTimeout,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/connect", relay.HandleConnect(b, cfg.IdleTimeout, cfg.MaxMessageSize))

	log.Printf("latch-relay listening on :%s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
		log.Fatal(err)
	}
}
