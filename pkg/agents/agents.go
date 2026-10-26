// Package agents manages AI agent access: the tokens agents use on SIEMLite's
// MCP endpoint, each with a level that says what it may do, and the switch that
// turns the endpoint on or off. It is the "AI agents (MCP)" integration.
package agents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"siemlite/pkg/auth"
	"siemlite/pkg/integrations"
	"siemlite/pkg/storage"
)

const enabledKey = "mcp_enabled"

// ErrBadToken is a missing, unknown or removed token.
var ErrBadToken = errors.New("invalid or removed agent token")

// Store is the storage the service needs.
type Store interface {
	CreateAgentToken(ctx context.Context, name, level, keyHash, createdBy string, nowMs int64) (int64, error)
	ListAgentTokens(ctx context.Context) ([]storage.AgentToken, error)
	FindAgentToken(ctx context.Context, keyHash string) (*storage.AgentToken, error)
	TouchAgentToken(ctx context.Context, id, nowMs int64) error
	DeleteAgentToken(ctx context.Context, id int64) (*storage.AgentToken, error)
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Service is the AI agents integration.
type Service struct {
	store Store
	now   func() time.Time

	mu      sync.Mutex
	touched map[int64]time.Time // when each token's last use was recorded
}

// New returns the service.
func New(store Store) *Service {
	return &Service{store: store, now: time.Now, touched: map[int64]time.Time{}}
}

// Levels are the access levels a token can have, in order.
var Levels = []string{storage.AgentRead, storage.AgentAnalyst, storage.AgentAdmin}

// LevelLabel names a level for people.
func LevelLabel(level string) string {
	switch level {
	case storage.AgentRead:
		return "read-only"
	case storage.AgentAnalyst:
		return "analyst"
	case storage.AgentAdmin:
		return "admin"
	}
	return level
}

func (s *Service) ID() string   { return "mcp" }
func (s *Service) Name() string { return "AI agents (MCP)" }
func (s *Service) Description() string {
	return "Let AI agents search logs, read alerts and make changes through the Model Context Protocol, with a token for each."
}

// Info reports how many tokens there are and whether agents are let in.
func (s *Service) Info(ctx context.Context) (integrations.Info, error) {
	tokens, err := s.store.ListAgentTokens(ctx)
	if err != nil {
		return integrations.Info{}, err
	}
	on, err := s.Enabled(ctx)
	if err != nil {
		return integrations.Info{}, err
	}
	info := integrations.Info{Configured: len(tokens) > 0, Enabled: on}
	if len(tokens) == 0 {
		return info, nil
	}
	count := map[string]int{}
	for _, t := range tokens {
		count[t.Level]++
	}
	var parts []string
	for _, l := range Levels {
		if count[l] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", count[l], LevelLabel(l)))
		}
	}
	noun := "tokens"
	if len(tokens) == 1 {
		noun = "token"
	}
	info.Summary = fmt.Sprintf("%d %s (%s)", len(tokens), noun, strings.Join(parts, ", "))
	return info, nil
}

// Enabled reports whether agents may connect (on unless switched off).
func (s *Service) Enabled(ctx context.Context) (bool, error) {
	v, err := s.store.Setting(ctx, enabledKey, "1")
	return v != "0", err
}

// SetEnabled lets agents in or keeps them out, keeping the tokens.
func (s *Service) SetEnabled(ctx context.Context, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return s.store.SetSetting(ctx, enabledKey, v)
}

// List returns the tokens.
func (s *Service) List(ctx context.Context) ([]storage.AgentToken, error) {
	return s.store.ListAgentTokens(ctx)
}

// Create makes a token. The token itself is returned once and not kept.
func (s *Service) Create(ctx context.Context, name, level, by string) (*storage.AgentToken, string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "" || len([]rune(name)) > 60:
		return nil, "", integrations.InputError("Give the token a name of 1-60 characters, such as the agent or person who will use it.")
	case strings.IndexFunc(name, unicode.IsControl) >= 0:
		return nil, "", integrations.InputError("The name can't contain control characters.")
	}
	valid := false
	for _, l := range Levels {
		valid = valid || l == level
	}
	if !valid {
		return nil, "", integrations.InputError("The level must be read, analyst or admin.")
	}
	token, hash, err := auth.GenerateAgentKey()
	if err != nil {
		return nil, "", err
	}
	id, err := s.store.CreateAgentToken(ctx, name, level, hash, by, s.now().UnixMilli())
	if errors.Is(err, storage.ErrAgentTokenExists) {
		return nil, "", integrations.InputError("A token with that name already exists.")
	}
	if err != nil {
		return nil, "", err
	}
	return &storage.AgentToken{ID: id, Name: name, Level: level, CreatedBy: by, CreatedAt: s.now().UnixMilli()}, token, nil
}

// Remove deletes a token; it stops working at once.
func (s *Service) Remove(ctx context.Context, id int64) (*storage.AgentToken, error) {
	t, err := s.store.DeleteAgentToken(ctx, id)
	if err == nil {
		s.mu.Lock()
		delete(s.touched, id)
		s.mu.Unlock()
	}
	return t, err
}

// Authenticate finds the token a request carries.
func (s *Service) Authenticate(ctx context.Context, token string) (*storage.AgentToken, error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, auth.AgentKeyPrefix) {
		return nil, ErrBadToken
	}
	t, err := s.store.FindAgentToken(ctx, auth.HashKey(token))
	if errors.Is(err, storage.ErrAgentTokenNotFound) {
		return nil, ErrBadToken
	}
	if err != nil {
		return nil, err
	}
	// Note the use at most once a minute, so a busy agent doesn't write on every call.
	now := s.now()
	s.mu.Lock()
	due := now.Sub(s.touched[t.ID]) >= time.Minute
	if due {
		s.touched[t.ID] = now
	}
	s.mu.Unlock()
	if due {
		_ = s.store.TouchAgentToken(ctx, t.ID, now.UnixMilli())
	}
	return t, nil
}
