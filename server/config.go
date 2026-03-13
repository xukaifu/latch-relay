package main

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port             string
	MaxChannelsTotal int
	MaxMessageSize   int64
	PairingTTL       time.Duration
	IdleTimeout      time.Duration
	ChallengeTimeout time.Duration
	WaitPeerTimeout  time.Duration
	MaxPairingsPerIP int
	MaxChannelsPerIP int
	TrustProxy       bool
}

func LoadConfig() Config {
	c := Config{
		Port:             "8081",
		MaxChannelsTotal: 10000,
		MaxMessageSize:   256 * 1024,
		PairingTTL:       10 * time.Minute,
		IdleTimeout:      60 * time.Second,
		ChallengeTimeout: 10 * time.Second,
		WaitPeerTimeout:  30 * time.Second,
	}
	if p := os.Getenv("PORT"); p != "" {
		c.Port = p
	}
	if n, err := strconv.Atoi(os.Getenv("MAX_CHANNELS")); err == nil && n > 0 {
		c.MaxChannelsTotal = n
	}
	if n, err := strconv.Atoi(os.Getenv("MAX_PAIRINGS_PER_IP")); err == nil && n > 0 {
		c.MaxPairingsPerIP = n
	}
	if n, err := strconv.Atoi(os.Getenv("MAX_CHANNELS_PER_IP")); err == nil && n > 0 {
		c.MaxChannelsPerIP = n
	}
	if os.Getenv("TRUST_PROXY") == "true" || os.Getenv("TRUST_PROXY") == "1" {
		c.TrustProxy = true
	}
	return c
}
