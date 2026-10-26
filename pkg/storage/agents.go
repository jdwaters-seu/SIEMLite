package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var (
	ErrAgentTokenNotFound = errors.New("agent token not found")
	ErrAgentTokenExists   = errors.New("an agent token with that name already exists")
)

// Agent token levels: what an AI agent may do through the MCP endpoint.
const (
	AgentRead    = "read"    // search events, read alerts, rules, sources and stats
	AgentAnalyst = "analyst" // also acknowledge and close alerts
	AgentAdmin   = "admin"   // also manage sources and parsers
)

// AgentToken is a credential for an AI agent. The token itself is shown once,
// when it is made; only its hash is stored.
type AgentToken struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Level      string `json:"level"`
	CreatedBy  string `json:"created_by"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt *int64 `json:"last_used_at"`
}

// CreateAgentToken stores a new token (by its hash) and returns its id.
func (r *Repository) CreateAgentToken(ctx context.Context, name, level, keyHash, createdBy string, nowMs int64) (int64, error) {
	res, err := r.db.Write.ExecContext(ctx, `INSERT INTO agent_tokens (name, level, key_hash, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, level, keyHash, createdBy, nowMs)
	if uniqueErr(err) {
		return 0, ErrAgentTokenExists
	}
	if err != nil {
		return 0, fmt.Errorf("create agent token: %w", err)
	}
	return res.LastInsertId()
}

// ListAgentTokens returns every token, oldest first.
func (r *Repository) ListAgentTokens(ctx context.Context) ([]AgentToken, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT id, name, level, created_by, created_at, last_used_at FROM agent_tokens ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list agent tokens: %w", err)
	}
	defer rows.Close()
	out := []AgentToken{}
	for rows.Next() {
		var t AgentToken
		var used sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Name, &t.Level, &t.CreatedBy, &t.CreatedAt, &used); err != nil {
			return nil, err
		}
		if used.Valid {
			t.LastUsedAt = &used.Int64
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// FindAgentToken returns the token whose hash is keyHash.
func (r *Repository) FindAgentToken(ctx context.Context, keyHash string) (*AgentToken, error) {
	var t AgentToken
	var used sql.NullInt64
	err := r.db.Read.QueryRowContext(ctx, `SELECT id, name, level, created_by, created_at, last_used_at FROM agent_tokens WHERE key_hash = ?`,
		keyHash).Scan(&t.ID, &t.Name, &t.Level, &t.CreatedBy, &t.CreatedAt, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAgentTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find agent token: %w", err)
	}
	if used.Valid {
		t.LastUsedAt = &used.Int64
	}
	return &t, nil
}

// TouchAgentToken records that a token was used.
func (r *Repository) TouchAgentToken(ctx context.Context, id, nowMs int64) error {
	_, err := r.db.Write.ExecContext(ctx, `UPDATE agent_tokens SET last_used_at = ? WHERE id = ?`, nowMs, id)
	return err
}

// DeleteAgentToken removes a token, so it stops working at once, and returns it.
func (r *Repository) DeleteAgentToken(ctx context.Context, id int64) (*AgentToken, error) {
	all, err := r.ListAgentTokens(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range all {
		if t.ID != id {
			continue
		}
		if _, err := r.db.Write.ExecContext(ctx, `DELETE FROM agent_tokens WHERE id = ?`, id); err != nil {
			return nil, fmt.Errorf("delete agent token: %w", err)
		}
		return &t, nil
	}
	return nil, ErrAgentTokenNotFound
}
