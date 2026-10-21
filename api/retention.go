package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
	"siemlite/pkg/ingest"
	"siemlite/pkg/retention"
)

// The System page's retention setting: how many days events are kept.

type retentionView struct {
	Days      int  `json:"days"`
	Default   int  `json:"default"`
	Min       int  `json:"min"`
	Max       int  `json:"max"`
	Saved     bool `json:"saved"` // chosen on the page, rather than -retention-days
	LateAfter int  `json:"late_after_days"`
	LateBurst int  `json:"late_burst"`
	Cleaning  bool `json:"cleaning,omitempty"`
}

func (s *Server) retentionState(ctx context.Context) retentionView {
	v := retentionView{Days: s.deps.Retention.Days(), Default: retention.DefaultDays, Min: retention.MinDays, Max: retention.MaxDays,
		LateAfter: int(ingest.LateAfter.Hours() / 24), LateBurst: ingest.LateBurst}
	if saved, err := s.deps.Repo.Setting(ctx, retention.SettingKey, ""); err == nil && saved != "" {
		v.Saved = true
	}
	return v
}

func (s *Server) handleGetRetention(w http.ResponseWriter, r *http.Request) {
	if s.deps.Retention == nil {
		writeError(w, http.StatusNotImplemented, "this server can't change how long events are kept")
		return
	}
	writeJSON(w, http.StatusOK, s.retentionState(r.Context()))
}

func (s *Server) handleSaveRetention(w http.ResponseWriter, r *http.Request) {
	if s.deps.Retention == nil {
		writeError(w, http.StatusNotImplemented, "this server can't change how long events are kept")
		return
	}
	var req struct {
		Days int `json:"days"`
	}
	if !decodeJSON(w, r, &req, 1<<10) {
		return
	}
	if req.Days < retention.MinDays || req.Days > retention.MaxDays {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Keep events between %d and %d days.", retention.MinDays, retention.MaxDays))
		return
	}
	was := s.deps.Retention.Days()
	if err := s.deps.Repo.SetSetting(r.Context(), retention.SettingKey, strconv.Itoa(req.Days)); err != nil {
		s.internal(w, "save the retention period", err)
		return
	}
	s.deps.Retention.SetDays(req.Days)
	if s.deps.Ingest != nil {
		s.deps.Ingest.SetMaxAge(time.Duration(req.Days) * 24 * time.Hour)
	}
	v := s.retentionState(r.Context())
	if req.Days < was {
		// Shorter: delete what is now too old straight away, not at the next daily clean.
		v.Cleaning = true
		go func() {
			n, err := s.deps.Retention.RunOnce(context.Background())
			if err != nil {
				s.deps.Logger.Error("cleaning up after the retention period was shortened failed", "err", err)
				return
			}
			s.deps.Logger.Info("retention period shortened; old events deleted", "days", req.Days, "deleted", n)
		}()
	}
	who := auth.FromContext(r.Context()).Name
	s.deps.Logger.Info("retention period changed", "from", was, "to", req.Days, "by", who)
	s.audit(r, audit.Entry{Action: "system.retention", Severity: map[bool]int{true: 4, false: 2}[req.Days < was],
		Message: fmt.Sprintf("%s set events to be kept %d days (was %d)", who, req.Days, was)})
	writeJSON(w, http.StatusOK, v)
}
