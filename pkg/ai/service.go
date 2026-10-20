package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"siemlite/pkg/integrations"
	"siemlite/pkg/secret"
)

// Where the model runs.
const (
	ProviderLocal = "local"      // Ollama, on this server
	ProviderCloud = "openrouter" // OpenRouter, in the cloud
)

// RecommendedCloud are OpenRouter's always-current names for small, fast,
// inexpensive models that answer in a given JSON shape. The first is the default.
var RecommendedCloud = []string{"~anthropic/claude-haiku-latest", "~google/gemini-flash-latest", "~openai/gpt-mini-latest", "~deepseek/deepseek-flash-latest"}

const settingKey = "ai"

// Settings are the AI Parsers settings, without the OpenRouter key.
type Settings struct {
	Provider   string `json:"provider"`
	OllamaURL  string `json:"ollama_url"`
	LocalModel string `json:"local_model"`
	CloudModel string `json:"cloud_model"`
	// SendAddresses sends IP and email addresses to a cloud model as they
	// are. Off (the default, and when left out) replaces them first.
	SendAddresses bool `json:"send_addresses"`
}

type stored struct {
	Settings
	Key      string `json:"key,omitempty"` // sealed
	Disabled bool   `json:"disabled,omitempty"`
}

// Defaults come from the command line (-ai-url, -ai-model). With a URL they
// are the settings until the page saves its own, so existing setups keep working.
type Defaults struct {
	OllamaURL string
	Model     string
}

// Store keeps settings (storage.Repository).
type Store interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// InputError is a mistake in what was entered, worded for the person.
type InputError = integrations.InputError

var (
	// ErrOff means AI Parsers is turned off or not set up.
	ErrOff = errors.New("AI Parsers is off")
	// ErrNotReady means the local model is still downloading or Ollama can't be reached.
	ErrNotReady = errors.New("the AI model isn't ready yet")
)

// PullStatus is a model download in progress, or the last one.
type PullStatus struct {
	Model     string `json:"model"`
	Status    string `json:"status"`
	Completed int64  `json:"completed"`
	Total     int64  `json:"total"`
	Error     string `json:"error,omitempty"`
	Running   bool   `json:"running"`
}

// Service is the AI Parsers integration.
type Service struct {
	// OpenRouterURL is OpenRouter's API; tests point it elsewhere.
	OpenRouterURL string

	store Store
	box   *secret.Box
	def   Defaults
	log   *slog.Logger
	http  *http.Client
	wake  chan struct{}

	mu         sync.Mutex
	cur        stored // as last loaded or saved
	loaded     bool
	hw         Hardware
	readyAt    string // "url|model" known to be downloaded
	pull       *PullStatus
	pullKey    string
	pullCancel context.CancelFunc
	cloud      []CloudModel
	cloudAt    time.Time
}

// NewService returns the integration. box seals the OpenRouter key.
func NewService(store Store, box *secret.Box, def Defaults, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if def.Model == "" {
		def.Model = DefaultModel
	}
	return &Service{OpenRouterURL: DefaultOpenRouter, store: store, box: box, def: def, log: log,
		http: &http.Client{Timeout: 3 * time.Minute}, wake: make(chan struct{}, 1), hw: DetectHardware()}
}

func (s *Service) load(ctx context.Context) (stored, error) {
	raw, err := s.store.Setting(ctx, settingKey, "")
	if err != nil {
		return stored{}, err
	}
	var st stored
	switch {
	case raw != "":
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			return stored{}, fmt.Errorf("saved AI Parsers settings are damaged: %w", err)
		}
	case s.def.OllamaURL != "":
		st.Settings = Settings{Provider: ProviderLocal, OllamaURL: s.def.OllamaURL, LocalModel: s.def.Model}
	}
	s.mu.Lock()
	s.cur, s.loaded = st, true
	s.mu.Unlock()
	return st, nil
}

func (s *Service) current(ctx context.Context) (stored, error) {
	s.mu.Lock()
	st, ok := s.cur, s.loaded
	s.mu.Unlock()
	if ok {
		return st, nil
	}
	return s.load(ctx)
}

func configured(st stored) bool {
	switch st.Provider {
	case ProviderLocal:
		return st.OllamaURL != "" && st.LocalModel != ""
	case ProviderCloud:
		return st.Key != "" && st.CloudModel != ""
	}
	return false
}

func (s *Service) model(st stored) string {
	if st.Provider == ProviderCloud {
		return st.CloudModel
	}
	return st.LocalModel
}

// defaultOllamaURL is where Ollama usually is: the compose service, or this machine.
func defaultOllamaURL() string {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if fileExists(f) {
			return "http://ollama:11434"
		}
	}
	return "http://localhost:11434"
}

// --- What the page shows ---

// OllamaState is what Ollama reported just now.
type OllamaState struct {
	Reachable bool         `json:"reachable"`
	Error     string       `json:"error,omitempty"`
	Installed []LocalModel `json:"installed"`
}

// View is the Integrations card. The key is never included.
type View struct {
	Settings
	Configured     bool         `json:"configured"`
	Enabled        bool         `json:"enabled"`
	Ready          bool         `json:"ready"`
	HasKey         bool         `json:"has_key"`
	KeyUnreadable  bool         `json:"key_unreadable,omitempty"`
	Hardware       Hardware     `json:"hardware"`
	Recommended    string       `json:"recommended"`
	Catalog        []Catalog    `json:"catalog"`
	CloudSuggested []string     `json:"cloud_recommended"`
	Ollama         *OllamaState `json:"ollama,omitempty"`
	Pull           *PullStatus  `json:"pull,omitempty"`
}

// Get returns the settings, with Ollama's state when it runs on this server.
func (s *Service) Get(ctx context.Context) (View, error) {
	st, err := s.load(ctx)
	if err != nil {
		return View{}, err
	}
	v := View{Settings: st.Settings, Configured: configured(st), HasKey: st.Key != "", Catalog: LocalCatalog, CloudSuggested: RecommendedCloud}
	v.Enabled = v.Configured && !st.Disabled
	if st.Key != "" {
		if _, err := s.box.Open(st.Key); err != nil {
			v.KeyUnreadable = true
		}
	}
	if v.OllamaURL == "" {
		v.OllamaURL = s.def.OllamaURL
		if v.OllamaURL == "" {
			v.OllamaURL = defaultOllamaURL()
		}
	}
	if v.CloudModel == "" {
		v.CloudModel = RecommendedCloud[0]
	}
	if v.Provider != ProviderCloud {
		o := newOllama(v.OllamaURL, "")
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		models, err := o.models(qctx)
		gpu := err == nil && o.usingGPU(qctx)
		cancel()
		ost := &OllamaState{Reachable: err == nil, Installed: models}
		if err != nil {
			ost.Error = shortErr(err)
		}
		v.Ollama = ost
		if gpu {
			s.mu.Lock()
			s.hw.GPU = true
			s.mu.Unlock()
		}
	}
	s.mu.Lock()
	v.Hardware = s.hw
	if s.pull != nil {
		p := *s.pull
		v.Pull = &p
	}
	v.Ready = v.Enabled && s.readyLocked(st)
	s.mu.Unlock()
	v.Recommended = Recommend(v.Hardware)
	if v.LocalModel == "" {
		v.LocalModel = v.Recommended
	}
	return v, nil
}

func (s *Service) readyLocked(st stored) bool {
	switch st.Provider {
	case ProviderCloud:
		return st.Key != ""
	case ProviderLocal:
		return s.readyAt == st.OllamaURL+"|"+st.LocalModel
	}
	return false
}

func shortErr(err error) string {
	m := err.Error()
	if i := strings.LastIndex(m, ": "); i >= 0 && strings.Contains(m, "dial") {
		m = m[i+2:]
	}
	return m
}

// --- Saving ---

var (
	localModelRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,99}$`)
	cloudModelRe = regexp.MustCompile(`^~?[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,119}$`)
)

// Save stores the settings. key nil keeps the saved OpenRouter key; "" removes it.
func (s *Service) Save(ctx context.Context, in Settings, key *string) error {
	in.OllamaURL = strings.TrimRight(strings.TrimSpace(in.OllamaURL), "/")
	in.LocalModel, in.CloudModel = strings.TrimSpace(in.LocalModel), strings.TrimSpace(in.CloudModel)
	old, err := s.load(ctx)
	if err != nil {
		return err
	}
	next := stored{Settings: in, Key: old.Key, Disabled: old.Disabled}
	if key != nil {
		k := strings.TrimSpace(*key)
		switch {
		case k == "":
			next.Key = ""
		case len(k) > 512 || strings.ContainsAny(k, " \t\r\n"):
			return InputError("That doesn't look like an OpenRouter API key.")
		default:
			if next.Key, err = s.box.Seal(k); err != nil {
				return err
			}
		}
	}
	switch in.Provider {
	case ProviderLocal:
		u, err := url.Parse(in.OllamaURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") {
			return InputError("The Ollama address must be an http or https address with no path, such as http://ollama:11434.")
		}
		if !localModelRe.MatchString(in.LocalModel) {
			return InputError("Choose a model, or enter an Ollama model name such as qwen2.5-coder:3b.")
		}
	case ProviderCloud:
		if !cloudModelRe.MatchString(in.CloudModel) {
			return InputError("Choose a model, or enter an OpenRouter model ID such as " + RecommendedCloud[0] + ".")
		}
		if next.Key == "" {
			return InputError("Enter your OpenRouter API key (from openrouter.ai/keys).")
		}
	default:
		return InputError("Choose where the model runs: on this server, or in the cloud with OpenRouter.")
	}
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingKey, string(b)); err != nil {
		return err
	}
	s.mu.Lock()
	s.cur, s.loaded = next, true
	s.mu.Unlock()
	s.nudge()
	return nil
}

func (s *Service) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// --- The integration ---

// ID is the integration's id.
func (s *Service) ID() string { return "ai" }

// Name is shown on its card.
func (s *Service) Name() string { return "AI Parsers" }

// Description is shown on its card.
func (s *Service) Description() string {
	return "Suggest a parser from sample log lines, with a model on this server or in the cloud."
}

// Info reports the card's state.
func (s *Service) Info(ctx context.Context) (integrations.Info, error) {
	st, err := s.load(ctx)
	if err != nil {
		return integrations.Info{}, err
	}
	info := integrations.Info{Configured: configured(st), Enabled: configured(st) && !st.Disabled}
	if !info.Configured {
		return info, nil
	}
	s.mu.Lock()
	ready, pull := s.readyLocked(st), s.pull
	s.mu.Unlock()
	switch st.Provider {
	case ProviderCloud:
		info.Summary = "In the cloud with OpenRouter: " + st.CloudModel + "."
	default:
		info.Summary = "On this server with Ollama: " + st.LocalModel + "."
		if info.Enabled && !ready {
			switch {
			case pull != nil && pull.Model == st.LocalModel && pull.Running && pull.Total > 0:
				info.Summary += fmt.Sprintf(" Downloading, %d%%.", pull.Completed*100/pull.Total)
			case pull != nil && pull.Model == st.LocalModel && pull.Error != "":
				info.Summary += " The download failed: " + pull.Error
			default:
				info.Summary += " Waiting for Ollama."
			}
		}
	}
	return info, nil
}

// SetEnabled turns it on or off, keeping the settings.
func (s *Service) SetEnabled(ctx context.Context, on bool) error {
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	if on && !configured(st) {
		return InputError("Set up AI Parsers first.")
	}
	st.Disabled = !on
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, settingKey, string(b)); err != nil {
		return err
	}
	s.mu.Lock()
	s.cur, s.loaded = st, true
	s.mu.Unlock()
	s.nudge()
	return nil
}

// Status is what the Parsers page needs: whether to offer suggestions.
type Status struct {
	Enabled  bool   `json:"enabled"`
	Ready    bool   `json:"ready"`
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`
}

// Status reports from memory, so it is cheap enough for every page load. A nil Service is off.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.cur
	if !configured(st) || st.Disabled {
		return Status{}
	}
	return Status{Enabled: true, Ready: s.readyLocked(st), Model: s.model(st), Provider: st.Provider}
}

// --- Keeping the local model ready ---

// Run keeps the chosen local model downloaded while AI Parsers is on, and
// re-reads the settings now and then (a restore or another change).
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		s.check(ctx)
		select {
		case <-ctx.Done():
			s.mu.Lock()
			if s.pullCancel != nil {
				s.pullCancel()
			}
			s.mu.Unlock()
			return
		case <-t.C:
		case <-s.wake:
		}
	}
}

func (s *Service) check(ctx context.Context) {
	st, err := s.load(ctx)
	if err != nil {
		s.log.Warn("couldn't read the AI Parsers settings", "err", err)
		return
	}
	want := ""
	if configured(st) && !st.Disabled && st.Provider == ProviderLocal {
		want = st.OllamaURL + "|" + st.LocalModel
	}
	s.mu.Lock()
	if s.pullCancel != nil && s.pullKey != want { // the choice changed: stop the old download
		s.pullCancel()
		s.pullCancel, s.pullKey = nil, ""
	}
	busy := s.pullCancel != nil
	s.mu.Unlock()
	if want == "" || busy {
		return
	}
	o := newOllama(st.OllamaURL, st.LocalModel)
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	models, err := o.models(qctx)
	if err == nil && o.usingGPU(qctx) {
		s.mu.Lock()
		s.hw.GPU = true
		s.mu.Unlock()
	}
	cancel()
	if err != nil {
		s.mu.Lock()
		wasReady := s.readyAt == want
		s.readyAt = ""
		s.mu.Unlock()
		if wasReady {
			s.log.Warn("Ollama can't be reached; AI parser suggestions are paused", "url", st.OllamaURL, "err", err)
		}
		return
	}
	if hasModel(models, st.LocalModel) {
		s.mu.Lock()
		if s.readyAt != want {
			s.log.Info("AI parser help is ready", "model", st.LocalModel, "url", st.OllamaURL)
		}
		s.readyAt = want
		s.mu.Unlock()
		return
	}
	// Download it, in the background, reporting progress to the page.
	pctx, pcancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.readyAt = ""
	s.pullKey, s.pullCancel = want, pcancel
	s.pull = &PullStatus{Model: st.LocalModel, Status: "starting", Running: true}
	s.mu.Unlock()
	s.log.Info("downloading the AI model; this happens once", "model", st.LocalModel)
	go func() {
		err := o.pull(pctx, func(status string, done, total int64) {
			s.mu.Lock()
			if s.pull != nil && s.pull.Model == st.LocalModel {
				s.pull.Status = status
				// Ollama reports each file of the model in turn; follow the largest.
				if total > 0 && total >= s.pull.Total {
					s.pull.Completed, s.pull.Total = done, total
				}
			}
			s.mu.Unlock()
		})
		s.mu.Lock()
		if s.pull != nil && s.pull.Model == st.LocalModel {
			s.pull.Running = false
			if err != nil && pctx.Err() == nil {
				s.pull.Error = err.Error()
			}
		}
		if s.pullKey == want {
			s.pullCancel, s.pullKey = nil, ""
		}
		s.mu.Unlock()
		pcancel()
		if err != nil && pctx.Err() == nil {
			s.log.Warn("AI model download failed; it will be retried", "model", st.LocalModel, "err", err)
		}
		s.nudge()
	}()
}

// --- Suggesting ---

// Suggest proposes a parser for sample lines with the chosen model.
func (s *Service) Suggest(ctx context.Context, lines []string) (*Suggestion, error) {
	if s == nil {
		return nil, ErrOff
	}
	st, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	if !configured(st) || st.Disabled {
		return nil, ErrOff
	}
	var ch chatter
	switch st.Provider {
	case ProviderCloud:
		key, err := s.box.Open(st.Key)
		if err != nil {
			return nil, InputError("The saved OpenRouter key can't be read on this server; enter it again on the Integrations page.")
		}
		ch = &openRouter{base: s.OpenRouterURL, key: key, model: st.CloudModel, http: s.http}
		if !st.SendAddresses {
			ch = newMasker(ch)
		}
	default:
		s.mu.Lock()
		ready := s.readyLocked(st)
		s.mu.Unlock()
		if !ready {
			return nil, ErrNotReady
		}
		ch = newOllama(st.OllamaURL, st.LocalModel)
	}
	return suggest(ctx, ch, s.log, lines)
}

// --- Testing ---

// TestResult is what a connection test found.
type TestResult struct {
	Provider   string       `json:"provider"`
	Installed  []LocalModel `json:"installed,omitempty"`
	HasModel   bool         `json:"has_model"`
	KeyLabel   string       `json:"key_label,omitempty"`
	CreditLeft *float64     `json:"credit_left,omitempty"`
	ModelKnown *bool        `json:"model_known,omitempty"`
}

// Test checks the form's settings (key nil uses the saved key) without saving.
func (s *Service) Test(ctx context.Context, in Settings, key *string) (TestResult, error) {
	switch in.Provider {
	case ProviderLocal:
		o := newOllama(strings.TrimSpace(in.OllamaURL), in.LocalModel)
		qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		models, err := o.models(qctx)
		if err != nil {
			return TestResult{}, fmt.Errorf("couldn't reach Ollama at %s: %s", in.OllamaURL, shortErr(err))
		}
		return TestResult{Provider: in.Provider, Installed: models, HasModel: hasModel(models, strings.TrimSpace(in.LocalModel))}, nil
	case ProviderCloud:
		k := ""
		if key != nil {
			k = strings.TrimSpace(*key)
		}
		if k == "" {
			st, err := s.load(ctx)
			if err != nil {
				return TestResult{}, err
			}
			if st.Key == "" {
				return TestResult{}, InputError("Enter your OpenRouter API key (from openrouter.ai/keys).")
			}
			if k, err = s.box.Open(st.Key); err != nil {
				return TestResult{}, InputError("The saved OpenRouter key can't be read on this server; enter it again.")
			}
		}
		o := &openRouter{base: s.OpenRouterURL, key: k, http: &http.Client{Timeout: 20 * time.Second}}
		label, left, err := o.keyInfo(ctx)
		if err != nil {
			return TestResult{}, err
		}
		r := TestResult{Provider: in.Provider, KeyLabel: label, CreditLeft: left}
		if models, err := s.CloudModels(ctx); err == nil {
			known := false
			for _, m := range models {
				known = known || m.ID == strings.TrimSpace(in.CloudModel)
			}
			r.ModelKnown = &known
		}
		return r, nil
	}
	return TestResult{}, InputError("Choose where the model runs: on this server, or in the cloud with OpenRouter.")
}

// CloudModels lists OpenRouter's models that can answer in a JSON shape,
// fetched at most once an hour.
func (s *Service) CloudModels(ctx context.Context) ([]CloudModel, error) {
	s.mu.Lock()
	if s.cloud != nil && time.Since(s.cloudAt) < time.Hour {
		c := s.cloud
		s.mu.Unlock()
		return c, nil
	}
	s.mu.Unlock()
	qctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	models, err := cloudModels(qctx, s.http, s.OpenRouterURL)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cloud, s.cloudAt = models, time.Now()
	s.mu.Unlock()
	return models, nil
}
