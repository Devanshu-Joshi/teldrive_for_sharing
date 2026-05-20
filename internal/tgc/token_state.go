package tgc

import (
	"sync"
	"time"
)

// TokenState tracks runtime health of bot tokens.
// This is an in-memory, isolated, process-local structure using sync.Map.
// It is explicitly non-persistent and has zero coupling to DB or Redis.
type TokenState struct {
	// cooldowns tracks when a token is eligible to be used again.
	// Key: string (token), Value: time.Time (expiration time)
	cooldowns sync.Map

	// revoked tracks tokens that have been permanently invalidated by Telegram.
	// Key: string (token), Value: struct{}
	revoked sync.Map
}

var globalTokenState = &TokenState{}

// SetCooldown places a token on cooldown until the specified expiration time.
func (s *TokenState) SetCooldown(token string, expiration time.Time) {
	s.cooldowns.Store(token, expiration)
}

// IsOnCooldown checks if a token is currently on cooldown.
func (s *TokenState) IsOnCooldown(token string) bool {
	val, ok := s.cooldowns.Load(token)
	if !ok {
		return false
	}
	expiration, ok := val.(time.Time)
	if !ok {
		return false // Should not happen
	}
	return time.Now().Before(expiration)
}

// ClearCooldown manually removes a token from cooldown.
func (s *TokenState) ClearCooldown(token string) {
	s.cooldowns.Delete(token)
}

// MarkRevoked permanently marks a token as revoked for the lifetime of this process.
func (s *TokenState) MarkRevoked(token string) {
	s.revoked.Store(token, struct{}{})
}

// IsRevoked checks if a token has been marked as revoked.
func (s *TokenState) IsRevoked(token string) bool {
	_, ok := s.revoked.Load(token)
	return ok
}

// GetGlobalTokenState returns the isolated process-local token state tracker.
func GetGlobalTokenState() *TokenState {
	return globalTokenState
}
