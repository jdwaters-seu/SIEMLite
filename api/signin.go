package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/storage"
)

// Sign-in restrictions (pkg/auth/signin.go): the built-in admin kept to the
// local port, and Microsoft-only sign-in. The Users page and the Entra card
// change them.

// signinRefreshEvery is how often the enforced policy is worked out again, so
// a change made from the command line or by a restore takes effect.
const signinRefreshEvery = 30 * time.Second

// RefreshSignin works out the enforced policy from the saved settings and
// whether Microsoft sign-in is on. If the settings can't be read, the policy
// in force is kept.
func (s *Server) RefreshSignin(ctx context.Context) {
	st, err := auth.LoadSigninSettings(ctx, s.deps.Repo)
	if err != nil {
		s.deps.Logger.Error("couldn't read the sign-in settings; keeping the ones in force", "err", err)
		return
	}
	s.deps.Auth.SetPolicy(st.Enforced(s.entraActive(ctx)))
}

func (s *Server) entraActive(ctx context.Context) bool {
	return s.deps.Entra != nil && s.deps.Entra.Active(ctx)
}

// RunSignin keeps the policy up to date until ctx ends.
func (s *Server) RunSignin(ctx context.Context) {
	t := time.NewTicker(signinRefreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RefreshSignin(ctx)
		}
	}
}

type signinView struct {
	auth.SigninSettings
	EntraActive bool `json:"entra_active"`
	// Enforced is what applies now.
	Enforced struct {
		AdminLocalOnly bool `json:"admin_local_only"`
		PasswordsOff   bool `json:"passwords_off"`
	} `json:"enforced"`
	// LocalPort is the local port's number ("" when there is none).
	LocalPort string `json:"local_port"`
	// Local is whether this request came in on the local port.
	Local bool `json:"local"`
	// AdminAccount is whether the built-in admin exists, is an Admin and is switched on.
	AdminAccount bool `json:"admin_account"`
}

func (s *Server) localPort() string {
	if s.deps.LocalAddr == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(s.deps.LocalAddr)
	if err != nil {
		return ""
	}
	return port
}

func (s *Server) builtinAdminReady(ctx context.Context) (bool, error) {
	u, _, err := s.deps.Repo.GetUserForLogin(ctx, auth.BuiltinAdmin)
	if errors.Is(err, storage.ErrUserNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return auth.IsBuiltinAdmin(u.Username, u.AuthProvider) && u.Role == auth.RoleAdmin && !u.Disabled, nil
}

func (s *Server) signinState(ctx context.Context) (signinView, error) {
	st, err := auth.LoadSigninSettings(ctx, s.deps.Repo)
	if err != nil {
		return signinView{}, err
	}
	v := signinView{SigninSettings: st, EntraActive: s.entraActive(ctx), LocalPort: s.localPort(), Local: auth.IsLocal(ctx)}
	p := st.Enforced(v.EntraActive)
	v.Enforced.AdminLocalOnly, v.Enforced.PasswordsOff = p.AdminLocalOnly, p.PasswordsOff
	if v.AdminAccount, err = s.builtinAdminReady(ctx); err != nil {
		return signinView{}, err
	}
	return v, nil
}

func (s *Server) handleGetSignin(w http.ResponseWriter, r *http.Request) {
	v, err := s.signinState(r.Context())
	if err != nil {
		s.internal(w, "read the sign-in settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSaveSignin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AdminLocalOnly *bool `json:"admin_local_only"`
		EntraOnly      *bool `json:"entra_only"`
	}
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	ctx := r.Context()
	s.signinMuSave.Lock()
	defer s.signinMuSave.Unlock()
	old, err := auth.LoadSigninSettings(ctx, s.deps.Repo)
	if err != nil {
		s.internal(w, "read the sign-in settings", err)
		return
	}
	next := old
	if req.AdminLocalOnly != nil {
		next.AdminLocalOnly = *req.AdminLocalOnly
	}
	if req.EntraOnly != nil {
		next.EntraOnly = *req.EntraOnly
	}
	if (next.AdminLocalOnly && !old.AdminLocalOnly) || (next.EntraOnly && !old.EntraOnly) {
		if s.deps.LocalAddr == "" {
			writeError(w, http.StatusBadRequest, "SIEMLite has no local port, so the admin account couldn't sign in anywhere. Start it with -local-addr (the Docker setup does this) and try again.")
			return
		}
	}
	if next.EntraOnly && !old.EntraOnly {
		if !s.entraActive(ctx) {
			writeError(w, http.StatusBadRequest, "Set up and turn on sign-in with Microsoft first.")
			return
		}
		ok, err := s.builtinAdminReady(ctx)
		if err != nil {
			s.internal(w, "check the admin account", err)
			return
		}
		if !ok {
			writeError(w, http.StatusBadRequest, "There's no local account named admin with the Admin role to fall back on if sign-in with Microsoft stops working. Add one (or switch it back on) first.")
			return
		}
	}
	if err := auth.SaveSigninSettings(ctx, s.deps.Repo, next); err != nil {
		s.internal(w, "save the sign-in settings", err)
		return
	}
	s.RefreshSignin(ctx)
	who := auth.FromContext(ctx).Name
	for _, c := range []struct {
		was, is bool
		on, off string
	}{
		{old.AdminLocalOnly, next.AdminLocalOnly, "kept the admin account to the server itself", "let the admin account sign in from anywhere"},
		{old.EntraOnly, next.EntraOnly, "turned password sign-in off: only Microsoft sign-in (and the admin account, on the server itself)", "turned password sign-in back on"},
	} {
		if c.was == c.is {
			continue
		}
		msg := c.off
		if c.is {
			msg = c.on
		}
		s.deps.Logger.Info("sign-in restriction changed", "change", msg, "by", who)
		s.audit(r, audit.Entry{Action: "system.signin", Class: audit.AccountChange, Severity: 4, Message: who + " " + msg})
	}
	v, err := s.signinState(ctx)
	if err != nil {
		s.internal(w, "read the sign-in settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// LocalHandler is the handler for the local port: every request is marked as
// coming from the server itself. It answers only connections from the server:
// loopback, and in a container the container's gateway, which is where the
// host's published port (on 127.0.0.1) connects from. Other containers on the
// network, and on older Docker other machines that route to the container's
// address, reach the port from their own addresses and are refused.
func (s *Server) LocalHandler() http.Handler {
	h := s.Handler()
	peers := localPeers()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a, ok := peerAddr(r.RemoteAddr); !ok || !(a.IsLoopback() || slices.Contains(peers, a)) {
			s.deps.Logger.Warn("local port refused a connection that isn't from this server", "remote", r.RemoteAddr)
			writeError(w, http.StatusForbidden, "this port only answers the server itself")
			return
		}
		h.ServeHTTP(w, r.WithContext(auth.WithLocal(r.Context())))
	})
}

// localPeers are the addresses besides loopback that count as the server:
// the default gateways, but only inside a container (outside one, the
// gateway is a router).
func localPeers() []netip.Addr {
	if !inContainer() {
		return nil
	}
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}
	return defaultGateways(string(b))
}

func inContainer() bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// defaultGateways reads /proc/net/route: the gateway of each default route,
// written as little-endian hex.
func defaultGateways(table string) []netip.Addr {
	var out []netip.Addr
	for _, line := range strings.Split(table, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		g, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || g == 0 {
			continue
		}
		a := netip.AddrFrom4([4]byte{byte(g), byte(g >> 8), byte(g >> 16), byte(g >> 24)})
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// StartLocal serves HTTPS on the local port (Deps.LocalAddr) until Shutdown.
// It must only be reachable from the server itself: bind it to localhost, or
// under Docker publish it on 127.0.0.1 only.
func (s *Server) StartLocal(cfg *tls.Config) error {
	s.local.TLSConfig = cfg
	if err := s.local.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
