package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		MaxPairingsPerIP: cfg.MaxPairingsPerIP,
		MaxChannelsPerIP: cfg.MaxChannelsPerIP,
		Debug:            cfg.Debug,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/monitor", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(b.Stats())
	})
	mux.HandleFunc("/v1/connect", relay.HandleConnect(b, cfg.IdleTimeout, cfg.MaxMessageSize, cfg.TrustProxy))

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: mux,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		b.Close()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	if cfg.Debug {
		log.Println("debug mode enabled")
	}
	log.Printf("latch-relay listening on :%s", cfg.Port)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
