package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const parserAnswer = `{"pattern":"Failed password for {user} from {src_ip} port {src_port} ssh2","fields":{},"category":3,"severity":{"from":"auto"}}`

// fakeCloud stands in for one service's API, recording what it is sent.
type fakeCloud struct {
	mu   sync.Mutex
	reqs []*http.Request
	body []map[string]any
}

func (f *fakeCloud) record(r *http.Request) map[string]any {
	var b map[string]any
	raw, _ := io.ReadAll(r.Body)
	json.Unmarshal(raw, &b)
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.body = append(f.body, b)
	f.mu.Unlock()
	return b
}

func anthropicServer(t *testing.T, f *fakeCloud) *httptest.Server {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("x-api-key") != "sk-ant-good" || r.Header.Get("anthropic-version") == "" {
			w.WriteHeader(401)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /models", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) {
			io.WriteString(w, `{"data":[{"id":"claude-sonnet-5-5","display_name":"Claude Sonnet 5.5"},{"id":"claude-haiku-4-5","display_name":"Claude Haiku 4.5"},{"id":"claude-opus-5-5","display_name":"Claude Opus 5.5"}]}`)
		}
	})
	mux.HandleFunc("POST /messages", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		b := f.record(r)
		tc, _ := b["tool_choice"].(map[string]any)
		tools, _ := b["tools"].([]any)
		if tc["type"] != "tool" || tc["name"] != "parser" || len(tools) != 1 || b["system"] == "" || b["max_tokens"] == nil {
			w.WriteHeader(400)
			io.WriteString(w, `{"type":"error","error":{"type":"invalid_request_error","message":"bad request shape"}}`)
			return
		}
		for _, m := range b["messages"].([]any) {
			if role := m.(map[string]any)["role"]; role != "user" && role != "assistant" {
				t.Errorf("Anthropic was sent a %v message", role)
			}
		}
		io.WriteString(w, `{"content":[{"type":"tool_use","name":"parser","input":`+parserAnswer+`}]}`)
	})
	return httptest.NewServer(mux)
}

func geminiServer(t *testing.T, f *fakeCloud, refuseSchema bool) *httptest.Server {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("x-goog-api-key") != "AIza-good" || r.URL.Query().Get("key") != "" {
			w.WriteHeader(403)
			io.WriteString(w, `{"error":{"code":403,"message":"API key not valid","status":"PERMISSION_DENIED"}}`)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /models", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) {
			io.WriteString(w, `{"models":[
				{"name":"models/gemini-2.5-flash","displayName":"Gemini 2.5 Flash","supportedGenerationMethods":["generateContent"]},
				{"name":"models/gemini-2.5-flash-lite","displayName":"Gemini 2.5 Flash-Lite","supportedGenerationMethods":["generateContent"]},
				{"name":"models/text-embedding-004","displayName":"Embedding","supportedGenerationMethods":["embedContent"]},
				{"name":"models/gemini-2.5-flash-image","displayName":"Image","supportedGenerationMethods":["generateContent"]}]}`)
		}
	})
	mux.HandleFunc("POST /models/", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		if !strings.HasSuffix(r.URL.Path, ":generateContent") {
			w.WriteHeader(404)
			return
		}
		b := f.record(r)
		gc, _ := b["generationConfig"].(map[string]any)
		if gc["responseMimeType"] != "application/json" || b["systemInstruction"] == nil {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"code":400,"message":"bad shape"}}`)
			return
		}
		if refuseSchema && gc["responseJsonSchema"] != nil {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"code":400,"message":"Invalid JSON payload received. Unknown name \"responseJsonSchema\""}}`)
			return
		}
		for _, c := range b["contents"].([]any) {
			if role := c.(map[string]any)["role"]; role != "user" && role != "model" {
				t.Errorf("Gemini was sent a %v turn", role)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"candidates": []any{map[string]any{"content": map[string]any{"parts": []any{map[string]any{"text": parserAnswer}}}}}})
	})
	return httptest.NewServer(mux)
}

// openAIServer serves OpenAI's API shape (NVIDIA's too). refuse lists the
// response_format types the model refuses.
func openAIServer(t *testing.T, f *fakeCloud, key string, refuse ...string) *httptest.Server {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}`)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /models", func(w http.ResponseWriter, r *http.Request) {
		if ok(w, r) {
			io.WriteString(w, `{"data":[{"id":"gpt-5-mini"},{"id":"gpt-4.1-mini"},{"id":"gpt-5"},{"id":"text-embedding-3-small"},{"id":"whisper-1"},{"id":"gpt-4o-realtime-preview"},{"id":"dall-e-3"},
				{"id":"meta/llama-3.3-70b-instruct"},{"id":"nvidia/llama-3.3-nemotron-super-49b-v1"},{"id":"nvidia/nv-embedqa-e5-v5"},{"id":"meta/llama-guard-4-12b"}]}`)
		}
	})
	mux.HandleFunc("POST /chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if !ok(w, r) {
			return
		}
		b := f.record(r)
		if rf, has := b["response_format"].(map[string]any); has && contains(refuse, rf["type"].(string)) {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":{"message":"response_format `+rf["type"].(string)+` is not supported by this model"}}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "```json\n" + parserAnswer + "\n```"}}}})
	})
	return httptest.NewServer(mux)
}

var sshSample = []string{
	"Failed password for root from 203.0.113.7 port 51234 ssh2",
	"Failed password for admin from 198.51.100.23 port 40022 ssh2",
}

func TestCloudServices(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		provider, key, bad, model, wantRec string
		server                             func(*fakeCloud) *httptest.Server
	}{
		{ProviderAnthropic, "sk-ant-good", "sk-ant-bad", "claude-haiku-4-5", "claude-haiku-4-5", func(f *fakeCloud) *httptest.Server { return anthropicServer(t, f) }},
		{ProviderGoogle, "AIza-good", "AIza-bad", "gemini-2.5-flash", "gemini-2.5-flash-lite", func(f *fakeCloud) *httptest.Server { return geminiServer(t, f, false) }},
		{ProviderOpenAI, "sk-proj-good", "sk-proj-bad", "gpt-5-mini", "gpt-5-mini", func(f *fakeCloud) *httptest.Server { return openAIServer(t, f, "sk-proj-good") }},
		{ProviderNVIDIA, "nvapi-good", "nvapi-bad", "meta/llama-3.3-70b-instruct", "meta/llama-3.3-70b-instruct", func(f *fakeCloud) *httptest.Server { return openAIServer(t, f, "nvapi-good") }},
	} {
		t.Run(c.provider, func(t *testing.T) {
			f := &fakeCloud{}
			srv := c.server(f)
			defer srv.Close()
			s, store := newTestService(t, Defaults{})
			s.CloudURLs = map[string]string{c.provider: srv.URL}

			// The key is checked by reading the model list.
			bad := c.bad
			if _, err := s.Test(ctx, Settings{Provider: c.provider, CloudModel: c.model}, &bad); err == nil || !strings.Contains(err.Error(), "refused the API key") {
				t.Errorf("wrong key = %v", err)
			}
			key := c.key
			models, rec, err := s.CloudModels(ctx, c.provider, &key)
			if err != nil || len(models) == 0 || len(rec) == 0 || rec[0] != c.wantRec {
				t.Fatalf("models = %+v, recommended %v, %v", models, rec, err)
			}
			for _, m := range models {
				if hasAny(m.ID, "embed", "whisper", "realtime", "dall-e", "guard", "image") {
					t.Errorf("%s listed", m.ID)
				}
			}
			if err := s.Save(ctx, Settings{Provider: c.provider, CloudModel: c.model}, "", &key); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(store.m[settingKey], c.key) {
				t.Error("the key was stored in the clear")
			}
			if st := s.Status(); !st.Enabled || !st.Ready || st.Provider != c.provider || st.Model != c.model {
				t.Errorf("status = %+v", st)
			}
			sug, err := s.Suggest(ctx, sshSample)
			if err != nil || sug.Matched != 2 {
				t.Fatalf("suggest = %+v %v", sug, err)
			}
			if len(f.body) == 0 {
				t.Fatal("nothing was sent")
			}
			for _, b := range f.body {
				raw, _ := json.Marshal(b)
				if strings.Contains(string(raw), "203.0.113.7") {
					t.Error("an address was sent unmasked")
				}
			}
			info, _ := s.Info(ctx)
			if !strings.Contains(info.Summary, c.model) {
				t.Errorf("summary = %q", info.Summary)
			}
		})
	}
}

// TestModelsThatRefuseASchema: a model that won't take the JSON shape is
// asked for any JSON, then plainly; Gemini without the schema.
func TestModelsThatRefuseASchema(t *testing.T) {
	ctx := context.Background()
	f := &fakeCloud{}
	srv := openAIServer(t, f, "k", "json_schema", "json_object")
	defer srv.Close()
	o := &openAICompat{service: "NVIDIA", base: srv.URL, key: "k", model: "m", http: http.DefaultClient}
	out, err := o.chat(ctx, []map[string]string{{"role": "user", "content": "x"}}, map[string]any{"type": "object"})
	if err != nil || out != parserAnswer || len(f.body) != 3 || f.body[2]["response_format"] != nil {
		t.Errorf("fallback = %q %v, %d requests", out, err, len(f.body))
	}
	g := &fakeCloud{}
	gs := geminiServer(t, g, true)
	defer gs.Close()
	gm := &gemini{base: gs.URL, key: "AIza-good", model: "gemini-x", http: http.DefaultClient}
	out, err = gm.chat(ctx, []map[string]string{{"role": "system", "content": "s"}, {"role": "user", "content": "x"}, {"role": "assistant", "content": "y"}}, map[string]any{"type": "object"})
	if err != nil || out != parserAnswer || len(g.body) != 2 {
		t.Errorf("gemini fallback = %q %v, %d requests", out, err, len(g.body))
	}
}

// TestSwitchingServicesKeepsKeys: each service keeps its key and model, and
// settings from before v0.22 (one OpenRouter key) carry over.
func TestSwitchingServicesKeepsKeys(t *testing.T) {
	ctx := context.Background()
	s, store := newTestService(t, Defaults{})
	sealed, _ := s.box.Seal("sk-or-old")
	store.SetSetting(ctx, settingKey, `{"provider":"openrouter","cloud_model":"~google/gemini-flash-latest","key":"`+sealed+`"}`)
	v, err := s.Get(ctx)
	if err != nil || !v.Configured || !v.HasKey || !v.HasKeys[ProviderCloud] || v.CloudModel != "~google/gemini-flash-latest" {
		t.Fatalf("old settings = %+v %v", v, err)
	}
	k := "sk-ant-x"
	if err := s.Save(ctx, Settings{Provider: ProviderAnthropic, CloudModel: "claude-haiku-4-5"}, "", &k); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, Settings{Provider: ProviderCloud, CloudModel: "~google/gemini-flash-latest"}, "", nil); err != nil {
		t.Fatalf("back to OpenRouter without retyping its key: %v", err)
	}
	v, _ = s.Get(ctx)
	if !v.HasKeys[ProviderCloud] || !v.HasKeys[ProviderAnthropic] || v.Models[ProviderAnthropic] != "claude-haiku-4-5" || v.CloudModel != "~google/gemini-flash-latest" {
		t.Errorf("after switching = %+v", v)
	}
	// Removing one service's key leaves the others.
	empty := ""
	if err := s.Save(ctx, Settings{Provider: ProviderCloud, CloudModel: "~google/gemini-flash-latest"}, ProviderAnthropic, &empty); err != nil {
		t.Fatal(err)
	}
	if v, _ = s.Get(ctx); v.HasKeys[ProviderAnthropic] || !v.HasKeys[ProviderCloud] {
		t.Errorf("after removing Anthropic's key = %+v", v.HasKeys)
	}
	if err := s.Save(ctx, Settings{Provider: ProviderOpenAI, CloudModel: "gpt-5-mini"}, "", nil); err == nil || !strings.Contains(err.Error(), "OpenAI API key") {
		t.Errorf("a service with no key = %v", err)
	}
}
