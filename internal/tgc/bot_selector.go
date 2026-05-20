package tgc

import (
	"context"
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9"
)

// BotOp represents the type of operation for bot selection
type BotOp string

const (
	BotOpStream BotOp = "stream"
	BotOpUpload BotOp = "upload"
)

// BotSelector selects the next bot for a user using round-robin
type BotSelector interface {
	// Next returns the next bot token for the given user and operation using round-robin.
	// Different operations (stream, upload) maintain separate counters.
	Next(ctx context.Context, op BotOp, userID int64, bots []string) (token string, index int, err error)
}

// selectorKey creates a unique key for user+operation combination
func selectorKey(op BotOp, userID int64) string {
	return fmt.Sprintf("%s:%d", op, userID)
}

// MemoryBotSelector provides in-memory round-robin bot selection.
// This is used when Redis is not available (single instance mode).
type MemoryBotSelector struct {
	mu      sync.Mutex
	currIdx map[string]int
}

// NewMemoryBotSelector creates a new in-memory bot selector.
func NewMemoryBotSelector() *MemoryBotSelector {
	return &MemoryBotSelector{
		currIdx: make(map[string]int),
	}
}

// Next returns the next bot token using in-memory round-robin.
func (s *MemoryBotSelector) Next(ctx context.Context, op BotOp, userID int64, bots []string) (string, int, error) {
	if len(bots) == 0 {
		return "", 0, fmt.Errorf("no bots available")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := selectorKey(op, userID)
	startIdx := s.currIdx[key]
	state := GetGlobalTokenState()

	for i := 0; i < len(bots); i++ {
		idx := (startIdx + i) % len(bots)
		token := bots[idx]
		
		if !state.IsOnCooldown(token) && !state.IsRevoked(token) {
			s.currIdx[key] = (idx + 1) % len(bots)
			return token, idx, nil
		}
	}

	return "", 0, fmt.Errorf("all %d bots are currently unavailable (cooldown/revoked)", len(bots))
}

// RedisBotSelector provides Redis-backed round-robin bot selection.
// This enables coordinated bot selection across multiple TelDrive instances.
type RedisBotSelector struct {
	client *redis.Client
}

// NewRedisBotSelector creates a new Redis-backed bot selector.
func NewRedisBotSelector(client *redis.Client) *RedisBotSelector {
	return &RedisBotSelector{client: client}
}

// Next returns the next bot token using Redis atomic increment for coordination.
func (s *RedisBotSelector) Next(ctx context.Context, op BotOp, userID int64, bots []string) (string, int, error) {
	if len(bots) == 0 {
		return "", 0, fmt.Errorf("no bots available")
	}

	key := fmt.Sprintf("teldrive:bot_idx:%s:%d", op, userID)
	state := GetGlobalTokenState()

	for i := 0; i < len(bots); i++ {
		// Atomic increment in Redis
		idx, err := s.client.Incr(ctx, key).Result()
		if err != nil {
			return "", 0, fmt.Errorf("redis incr failed: %w", err)
		}

		// Convert to 0-based index and wrap around
		actualIdx := int((idx - 1) % int64(len(bots)))
		token := bots[actualIdx]

		if !state.IsOnCooldown(token) && !state.IsRevoked(token) {
			return token, actualIdx, nil
		}
	}

	return "", 0, fmt.Errorf("all %d bots are currently unavailable (cooldown/revoked)", len(bots))
}

func NewBotSelector(redisClient *redis.Client) BotSelector {
	if redisClient != nil {
		return NewRedisBotSelector(redisClient)
	}
	return NewMemoryBotSelector()
}
