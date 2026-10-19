package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"siemlite/pkg/storage"
)

// Sign-in restrictions: the built-in admin account can be kept to the server
// itself, and password sign-in can be turned off for everyone else while
// Microsoft sign-in is on.
//
// "On the server itself" means the request came in on SIEMLite's local port
// (-local-addr), never an address: behind Docker or a proxy on the same
// machine, visitors from anywhere can arrive from a local-looking address,
// but the local port is only published on the server's loopback interface.

// BuiltinAdmin is the name of the admin account made on first start.
const BuiltinAdmin = "admin"

// IsBuiltinAdmin reports whether an account is the built-in admin: the local
// (password) account named admin.
func IsBuiltinAdmin(username, provider string) bool {
	return provider == storage.ProviderLocal && strings.EqualFold(username, BuiltinAdmin)
}

// SigninSettings are the stored restrictions, as an admin chose them.
type SigninSettings struct {
	// AdminLocalOnly keeps the built-in admin account to the local port.
	AdminLocalOnly bool `json:"admin_local_only"`
	// EntraOnly turns password sign-in off for every other account while
	// Microsoft sign-in is on. The built-in admin can still sign in on the
	// local port, so a broken Entra setup can't lock everyone out.
	EntraOnly bool `json:"entra_only"`
}

// SigninSettingKey is where SigninSettings are stored.
const SigninSettingKey = "signin_policy"

// SettingStore reads and writes settings (storage.Repository).
type SettingStore interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// LoadSigninSettings reads the stored restrictions (none if never set).
func LoadSigninSettings(ctx context.Context, st SettingStore) (SigninSettings, error) {
	var s SigninSettings
	raw, err := st.Setting(ctx, SigninSettingKey, "")
	if err != nil || raw == "" {
		return s, err
	}
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return SigninSettings{}, fmt.Errorf("saved sign-in settings are damaged: %w", err)
	}
	return s, nil
}

// SaveSigninSettings stores the restrictions.
func SaveSigninSettings(ctx context.Context, st SettingStore, s SigninSettings) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.SetSetting(ctx, SigninSettingKey, string(b))
}

// Policy is what is enforced right now.
type Policy struct {
	// AdminLocalOnly: the built-in admin signs in, and its sessions work,
	// only on the local port.
	AdminLocalOnly bool
	// PasswordsOff: no other local account may sign in or use its session.
	PasswordsOff bool
}

// Enforced turns the stored settings into the policy, given whether Microsoft
// sign-in is on. Microsoft-only sign-in does nothing while it is off (so
// switching Entra off brings passwords back), and while it is on the
// built-in admin is kept to the local port.
func (s SigninSettings) Enforced(entraActive bool) Policy {
	off := s.EntraOnly && entraActive
	return Policy{AdminLocalOnly: s.AdminLocalOnly || off, PasswordsOff: off}
}

var (
	// ErrLocalOnly refuses the built-in admin away from the local port.
	ErrLocalOnly = errors.New("This account can only sign in on the server itself, at SIEMLite's local address (such as https://localhost:8444).")
	// ErrPasswordsOff refuses password sign-in while only Microsoft sign-in is allowed.
	ErrPasswordsOff = errors.New("Password sign-in is turned off. Sign in with Microsoft.")
)

type localKey struct{}

// WithLocal marks a request as having come in on the local port.
func WithLocal(ctx context.Context) context.Context { return context.WithValue(ctx, localKey{}, true) }

// IsLocal reports whether a request came in on the local port.
func IsLocal(ctx context.Context) bool { v, _ := ctx.Value(localKey{}).(bool); return v }

// SetPolicy changes what is enforced, for sign-ins and for every request.
func (a *Authenticator) SetPolicy(p Policy) { a.policy.Store(&p) }

// Policy is what is enforced now.
func (a *Authenticator) Policy() Policy {
	if p := a.policy.Load(); p != nil {
		return *p
	}
	return Policy{}
}

// passwordAllowed decides by the typed name alone, before any lookup, so a
// refusal says nothing about whether the account exists or the password.
func (a *Authenticator) passwordAllowed(ctx context.Context, username string) error {
	p := a.Policy()
	if strings.EqualFold(strings.TrimSpace(username), BuiltinAdmin) {
		if p.AdminLocalOnly && !IsLocal(ctx) {
			return ErrLocalOnly
		}
		return nil
	}
	if p.PasswordsOff {
		return ErrPasswordsOff
	}
	return nil
}

// sessionAllowed applies the same rules to a signed-in account on each request,
// so a restriction takes effect at once, sessions included.
func (a *Authenticator) sessionAllowed(ctx context.Context, username, provider string) bool {
	if provider != storage.ProviderLocal {
		return true
	}
	p := a.Policy()
	if IsBuiltinAdmin(username, provider) {
		return !p.AdminLocalOnly || IsLocal(ctx)
	}
	return !p.PasswordsOff
}
