package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"siemlite/pkg/ai"
	"siemlite/pkg/audit"
	"siemlite/pkg/auth"
)

// The AI Parsers card on the Integrations page (pkg/ai).

// aiRequest is the card's form. OpenRouterKey is a pointer so the form can
// keep the saved key (absent), replace it, or remove it ("").
type aiRequest struct {
	ai.Settings
	OpenRouterKey *string `json:"openrouter_key"`
}

func (s *Server) aiReady(w http.ResponseWriter) bool {
	if s.deps.AI == nil {
		writeError(w, http.StatusNotImplemented, "this server can't use AI Parsers")
		return false
	}
	return true
}

func (s *Server) handleGetAI(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	v, err := s.deps.AI.Get(r.Context())
	if err != nil {
		s.internal(w, "read the AI Parsers settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleSaveAI(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var req aiRequest
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	if err := s.deps.AI.Save(r.Context(), req.Settings, req.OpenRouterKey); err != nil {
		var bad ai.InputError
		if errors.As(err, &bad) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.internal(w, "save the AI Parsers settings", err)
		return
	}
	who := auth.FromContext(r.Context()).Name
	msg := fmt.Sprintf("%s set AI Parsers to run on this server with Ollama at %s, model %s", who, req.OllamaURL, req.LocalModel)
	if req.Provider == ai.ProviderCloud {
		msg = fmt.Sprintf("%s set AI Parsers to run in the cloud with OpenRouter, model %s, addresses %s", who, req.CloudModel,
			map[bool]string{false: "replaced before sending", true: "sent as they are"}[req.SendAddresses])
	}
	if req.OpenRouterKey != nil {
		msg += map[bool]string{true: ", and removed the OpenRouter key", false: ", and changed the OpenRouter key"}[*req.OpenRouterKey == ""]
	}
	s.deps.Logger.Info("AI Parsers settings changed", "by", who, "provider", req.Provider)
	s.audit(r, audit.Entry{Action: "system.ai.save", Severity: 3, Message: msg})
	v, err := s.deps.AI.Get(r.Context())
	if err != nil {
		s.internal(w, "read the AI Parsers settings", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleTestAI checks the form's settings against Ollama or OpenRouter without saving.
func (s *Server) handleTestAI(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	var req aiRequest
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Minute))
	res, err := s.deps.AI.Test(r.Context(), req.Settings, req.OpenRouterKey)
	var bad ai.InputError
	switch {
	case errors.As(err, &bad):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleCloudModels lists OpenRouter's models for the card's model list.
func (s *Server) handleCloudModels(w http.ResponseWriter, r *http.Request) {
	if !s.aiReady(w) {
		return
	}
	models, err := s.deps.AI.CloudModels(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models, "recommended": ai.RecommendedCloud})
}
