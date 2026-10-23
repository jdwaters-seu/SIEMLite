package api

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/entra"
)

// ssoCookie remembers one sign-in with Microsoft between sending the person
// there and their coming back. It is sealed, and SameSite=Lax because the
// return is a cross-site navigation (Strict would drop it).
const ssoCookie = "siemlite_sso"

// entraRequest is the Entra card's form. ClientSecret is a pointer so the form
// can say "keep the saved one" (absent) or replace it.
type entraRequest struct {
	entra.Config
	ClientSecret *string `json:"client_secret"`
}

func (s *Server) entraReady(w http.ResponseWriter) bool {
	if s.deps.Entra == nil {
		writeError(w, http.StatusNotImplemented, "this server can't sign people in with Microsoft")
		return false
	}
	return true
}

func (r entraRequest) check() error {
	if r.ClientSecret != nil && len(*r.ClientSecret) > 512 {
		return errors.New("The client secret is too long.")
	}
	return nil
}

func (s *Server) handleGetEntra(w http.ResponseWriter, r *http.Request) {
	if !s.entraReady(w) {
		return
	}
	v, err := s.deps.Entra.Get(r.Context())
	if err != nil {
		s.internal(w, "read Entra settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSaveEntra(w http.ResponseWriter, r *http.Request) {
	if !s.entraReady(w) {
		return
	}
	var req entraRequest
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	if err := req.check(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	who := auth.FromContext(r.Context()).Name
	if err := s.deps.Entra.Save(r.Context(), req.Config, req.ClientSecret); err != nil {
		var bad entra.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.internal(w, "save Entra settings", err)
		return
	}
	msg := who + " removed the Microsoft Entra settings"
	if strings.TrimSpace(req.TenantID) != "" {
		msg = fmt.Sprintf("%s set sign-in with Microsoft to tenant %s, app %s, access group %s", who,
			strings.ToLower(strings.TrimSpace(req.TenantID)), strings.ToLower(strings.TrimSpace(req.ClientID)), strings.ToLower(strings.TrimSpace(req.AccessGroupID)))
		if req.AdminGroupID != "" {
			msg += ", admin group " + strings.ToLower(strings.TrimSpace(req.AdminGroupID))
		}
		if req.ClientSecret != nil {
			msg += ", and changed the client secret"
		}
	}
	s.RefreshSignin(r.Context())
	s.deps.Logger.Info("Entra settings changed", "by", who)
	s.audit(r, audit.Entry{Action: "system.entra.save", Severity: 4, Message: msg})
	v, err := s.deps.Entra.Get(r.Context())
	if err != nil {
		s.internal(w, "read Entra settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleTestEntra checks the form's settings (or the saved ones) against Entra
// without saving, and says what it found.
func (s *Server) handleTestEntra(w http.ResponseWriter, r *http.Request) {
	if !s.entraReady(w) {
		return
	}
	var req entraRequest
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	if err := req.check(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Minute))
	who := auth.FromContext(r.Context()).Name
	res, err := s.deps.Entra.Test(r.Context(), &req.Config, req.ClientSecret)
	var bad entra.InputError
	if errors.As(err, &bad) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		s.deps.Logger.Warn("Entra test failed", "by", who, "err", err)
		s.audit(r, audit.Entry{Action: "system.entra.test", Severity: 2, Message: who + " tested the Microsoft Entra connection and it failed"})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r, audit.Entry{Action: "system.entra.test", Message: who + " tested the Microsoft Entra connection"})
	writeJSON(w, http.StatusOK, res)
}

// handleSyncEntra checks the access group now, instead of waiting for the next
// scheduled check.
func (s *Server) handleSyncEntra(w http.ResponseWriter, r *http.Request) {
	if !s.entraReady(w) {
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
	who := auth.FromContext(r.Context()).Name
	st, err := s.deps.Entra.Sync(r.Context())
	if errors.Is(err, entra.ErrNotActive) {
		writeError(w, http.StatusBadRequest, "Sign-in with Microsoft isn't set up and turned on.")
		return
	}
	if err != nil {
		s.deps.Logger.Warn("Entra membership check failed", "by", who, "err", err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "status": st})
		return
	}
	s.audit(r, audit.Entry{Action: "system.entra.sync", Message: fmt.Sprintf("%s checked the Microsoft Entra access group: %d in the group, %d accounts, %d switched off, %d switched on",
		who, st.Members, st.Accounts, st.Disabled, st.Enabled)})
	writeJSON(w, http.StatusOK, st)
}

// handleProviders tells the sign-in page which "sign in with" buttons to show.
func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	// password is false when only Microsoft sign-in is allowed here (the
	// built-in admin's sign-in is on the local port, where it stays true).
	p := s.deps.Auth.Policy()
	writeJSON(w, http.StatusOK, map[string]bool{"entra": s.entraActive(r.Context()),
		"password": !p.PasswordsOff || auth.IsLocal(r.Context()), "local": auth.IsLocal(r.Context())})
}

func (s *Server) ssoRedirect(w http.ResponseWriter, r *http.Request, errCode string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	to := "/"
	if errCode != "" {
		to = "/?sso_error=" + url.QueryEscape(errCode)
	}
	http.Redirect(w, r, to, http.StatusFound)
}

func clearSSOCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/api/v1/auth/entra", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
}

// handleEntraStart sends the browser to Microsoft to sign in.
func (s *Server) handleEntraStart(w http.ResponseWriter, r *http.Request) {
	if s.deps.Entra == nil || !s.deps.Auth.AttemptsAllowed(s.clientIP(r)) {
		s.ssoRedirect(w, r, "off")
		return
	}
	authURL, cookie, err := s.deps.Entra.BeginLogin(r.Context())
	if err != nil {
		if !errors.Is(err, entra.ErrNotActive) {
			s.deps.Logger.Error("Entra sign-in couldn't start", "err", err)
		}
		s.ssoRedirect(w, r, "off")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: cookie, Path: "/api/v1/auth/entra", MaxAge: int((10 * time.Minute).Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleEntraCallback is where Microsoft sends the person back. It never shows
// text that came from Microsoft: failures go to the sign-in page as a short code.
func (s *Server) handleEntraCallback(w http.ResponseWriter, r *http.Request) {
	clearSSOCookie(w)
	if s.deps.Entra == nil {
		s.ssoRedirect(w, r, "off")
		return
	}
	ip := s.clientIP(r)
	if !s.deps.Auth.AttemptsAllowed(ip) {
		s.ssoRedirect(w, r, "too_many")
		return
	}
	q := r.URL.Query()
	if q.Get("error") != "" { // the person cancelled, or Microsoft refused them
		s.auditSignin(r, audit.Entry{Action: "signin.sso.denied", Actor: "unknown", Class: audit.Authentication, Severity: 2,
			Message: "Sign-in with Microsoft was cancelled or refused at Microsoft"})
		s.ssoRedirect(w, r, entra.CodeDenied)
		return
	}
	var cookie string
	if c, err := r.Cookie(ssoCookie); err == nil {
		cookie = c.Value
	}
	// A browser can send the callback twice, a moment apart or at once (a
	// link checker, an extension, a retrying proxy). The code works once, so
	// the second would fail and be recorded as a failed sign-in right after
	// the real one. A repeat is answered like the first instead.
	f, first := s.ssoFlightFor(q.Get("state"), cookie)
	if f != nil && !first {
		select {
		case <-f.done:
			if f.token != "" {
				auth.SetSessionCookie(w, f.token)
			}
			s.ssoRedirect(w, r, f.code)
		case <-time.After(30 * time.Second):
			s.ssoRedirect(w, r, entra.CodeFailed)
		case <-r.Context().Done():
		}
		return
	}
	if f == nil && s.ssoSeen(q.Get("state")) { // the same sign-in again, without its cookie: the first one already ran
		s.ssoRedirect(w, r, "")
		return
	}
	token, code := s.completeEntra(r, ip, q.Get("code"), q.Get("state"), cookie)
	if f != nil {
		f.token, f.code = token, code
		close(f.done)
	}
	if token != "" {
		auth.SetSessionCookie(w, token)
	}
	s.ssoRedirect(w, r, code)
}

// ssoFlight is one sign-in's callback, kept for a short while so that a repeat
// of it gets the same answer.
type ssoFlight struct {
	done   chan struct{}
	cookie [sha256.Size]byte
	made   time.Time
	token  string // the session, if the sign-in worked
	code   string // else why not ("" when it did)
}

const (
	ssoFlightTTL = 2 * time.Minute
	ssoFlightMax = 2000
)

func ssoKey(state string) [sha256.Size]byte { return sha256.Sum256([]byte(state)) }

// ssoFlightFor registers this callback, or finds the earlier one it repeats.
// Only a callback that carries a flow cookie is registered, and a repeat must
// carry the same cookie to share the first one's session: the state alone is
// in the address bar and must not be enough to take a session.
func (s *Server) ssoFlightFor(state, cookie string) (f *ssoFlight, first bool) {
	if state == "" || cookie == "" {
		return nil, false
	}
	key, ck := ssoKey(state), sha256.Sum256([]byte(cookie))
	s.ssoMu.Lock()
	defer s.ssoMu.Unlock()
	now := time.Now()
	if len(s.ssoFlights) >= ssoFlightMax {
		for k, v := range s.ssoFlights {
			if now.Sub(v.made) > ssoFlightTTL {
				delete(s.ssoFlights, k)
			}
		}
		if len(s.ssoFlights) >= ssoFlightMax {
			clear(s.ssoFlights)
		}
	}
	if old, ok := s.ssoFlights[key]; ok && now.Sub(old.made) <= ssoFlightTTL {
		if old.cookie == ck {
			return old, false
		}
		return nil, false
	}
	if s.ssoFlights == nil {
		s.ssoFlights = map[[sha256.Size]byte]*ssoFlight{}
	}
	f = &ssoFlight{done: make(chan struct{}), cookie: ck, made: now}
	s.ssoFlights[key] = f
	return f, true
}

// ssoSeen reports whether a callback for this state has run lately.
func (s *Server) ssoSeen(state string) bool {
	if state == "" {
		return false
	}
	s.ssoMu.Lock()
	defer s.ssoMu.Unlock()
	f, ok := s.ssoFlights[ssoKey(state)]
	return ok && time.Since(f.made) <= ssoFlightTTL
}

// completeEntra finishes a sign-in and records it. It returns the new session's
// token, or else the short code of why it failed.
func (s *Server) completeEntra(r *http.Request, ip, code, state, cookie string) (token, errCode string) {
	user, err := s.deps.Entra.CompleteLogin(r.Context(), code, state, cookie)
	if err != nil {
		var le *entra.LoginError
		if !errors.As(err, &le) {
			le = &entra.LoginError{Code: entra.CodeFailed, Detail: err.Error()}
		}
		s.deps.Logger.Warn("sign-in with Microsoft failed", "code", le.Code, "detail", le.Detail, "remote", ip)
		msg := "Sign-in with Microsoft failed"
		switch le.Code {
		case entra.CodeNotInGroup, entra.CodeNameTaken:
			// The detail starts with the verified account name.
			msg = "Sign-in with Microsoft refused: " + le.Detail
		case entra.CodeFailed, entra.CodeExpired:
			s.deps.Auth.RecordFailure(ip)
		}
		s.auditSignin(r, audit.Entry{Action: "signin.sso.failed", Actor: "unknown", Class: audit.Authentication, Severity: 3, Message: msg,
			Fields: map[string]string{"reason": le.Code}})
		return "", le.Code
	}
	token, err = s.deps.Auth.StartSession(r.Context(), user)
	if err != nil {
		s.deps.Logger.Error("starting a session after Microsoft sign-in failed", "err", err)
		return "", entra.CodeFailed
	}
	// Turning sign-in with Microsoft off ends every Microsoft session. A sign-in
	// that was already under way could finish just after that, so check again now
	// that the session exists: if it was turned off in between, this session is
	// either ended by that, or ended here.
	if !s.deps.Entra.Active(r.Context()) {
		if err := s.deps.Auth.EndSession(r.Context(), token); err != nil {
			s.deps.Logger.Error("couldn't end a session started as sign-in with Microsoft was turned off", "err", err)
		}
		return "", "off"
	}
	s.audit(r, audit.Entry{Action: "signin.sso", Actor: user.Username, Class: audit.Authentication, Message: (&auth.Principal{Name: user.Username, DisplayName: user.DisplayName}).Label() + " signed in with Microsoft"})
	return token, ""
}
