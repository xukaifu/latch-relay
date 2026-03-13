package relay

import (
	"sync"
	"time"
)

// RateLimiter provides per-key sliding-window rate limiting.
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time
	limit   int
	window  time.Duration
}

// NewRateLimiter creates a rate limiter allowing limit events per window.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		windows: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
	}
}

// Allow returns true if the event is within the rate limit for the given key.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	times := rl.windows[key]
	// Remove expired entries
	start := 0
	for start < len(times) && times[start].Before(cutoff) {
		start++
	}
	times = times[start:]

	if len(times) == 0 {
		delete(rl.windows, key)
	}

	if len(times) >= rl.limit {
		rl.windows[key] = times
		return false
	}

	rl.windows[key] = append(times, now)
	return true
}

// Cleanup removes all keys whose timestamps have all expired outside the window.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.window)
	for key, times := range rl.windows {
		// Find if any timestamp is within the window
		allExpired := true
		for _, t := range times {
			if !t.Before(cutoff) {
				allExpired = false
				break
			}
		}
		if allExpired {
			delete(rl.windows, key)
		}
	}
}
