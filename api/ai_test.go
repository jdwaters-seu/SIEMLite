package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"siemlite/pkg/auth"
)

// TestAIParsersIntegration: the card's settings, the key kept secret, the
// switch, and suggestions only while it is on.
func TestAIParsersIntegration(t *testing.T) {
	e := newEnv(t)
	or := http.NewServeMux()
	or.HandleFunc("GET /key", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-or-good" {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"bad key"}}`)
			return
		}
		io.WriteString(w, `{"data":{"label":"test","limit_remaining":1}}`)
	})
	or.HandleFunc("GET /models", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":[{"id":"~anthropic/claude-haiku-latest","name":"Haiku","supported_parameters":["structured_outputs"],"pricing":{"prompt":"0.000001","completion":"0.000005"}}]}`)
	})
	or.HandleFunc("POST /chat/completions", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"choices": []map[string]any{{"message": map[string]any{"content": `{"pattern":"Failed password for {user} from {src_ip} port {src_port} ssh2","fields":{},"category":3,"severity":{"from":"auto"}}`}}}})
	})
	fake := httptest.NewServer(or)
	defer fake.Close()
	e.deps.AI.OpenRouterURL = fake.URL

	e.user("root", auth.RoleAdmin)
	e.user("sam", auth.RoleStandard)
	root, sam := e.client(), e.client()
	e.login(root, "root", password)
	e.login(sam, "sam", password)
	lines := map[string]any{"lines": []string{"Failed password for root from 203.0.113.7 port 51234 ssh2", "Failed password for bob from 198.51.100.2 port 4022 ssh2"}}

	for _, path := range []string{"/api/v1/integrations/ai", "/api/v1/integrations/ai/cloud-models"} {
		if got := e.call(sam, "GET", path, nil, nil, nil); got != 403 {
			t.Errorf("standard user %s = %d", path, got)
		}
	}
	var v map[string]any
	if got := e.call(root, "GET", "/api/v1/integrations/ai", nil, &v, nil); got != 200 || v["configured"] != false || v["recommended"] == "" || v["hardware"] == nil {
		t.Fatalf("empty = %d %v", got, v)
	}
	var er map[string]string
	if got := e.call(root, "POST", "/api/v1/parsers/suggest", lines, &er, nil); got != 404 || !strings.Contains(er["error"], "Integrations page") {
		t.Errorf("suggest before set up = %d %v", got, er)
	}
	cloud := map[string]any{"provider": "openrouter", "cloud_model": "~anthropic/claude-haiku-latest"}
	if got := e.call(root, "PUT", "/api/v1/integrations/ai", cloud, &er, nil); got != 400 || !strings.Contains(er["error"], "API key") {
		t.Errorf("cloud without a key = %d %v", got, er)
	}
	cloud["openrouter_key"] = "sk-or-wrong"
	if got := e.call(root, "POST", "/api/v1/integrations/ai/test", cloud, &er, nil); got != 502 || !strings.Contains(er["error"], "refused the API key") {
		t.Errorf("test with a wrong key = %d %v", got, er)
	}
	cloud["openrouter_key"] = "sk-or-good"
	if got := e.call(root, "PUT", "/api/v1/integrations/ai", cloud, &v, nil); got != 200 || v["enabled"] != true || v["has_key"] != true {
		t.Fatalf("save = %d %v", got, v)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "sk-or-good") {
		t.Error("the key came back")
	}
	var models struct {
		Models      []map[string]any `json:"models"`
		Recommended []string         `json:"recommended"`
	}
	if got := e.call(root, "GET", "/api/v1/integrations/ai/cloud-models", nil, &models, nil); got != 200 || len(models.Models) != 1 || len(models.Recommended) == 0 {
		t.Errorf("cloud models = %d %+v", got, models)
	}
	var me struct {
		AI struct {
			Enabled  bool   `json:"enabled"`
			Ready    bool   `json:"ready"`
			Provider string `json:"provider"`
		} `json:"ai"`
	}
	if e.call(sam, "GET", "/api/v1/me", nil, &me, nil); !me.AI.Enabled || !me.AI.Ready || me.AI.Provider != "openrouter" {
		t.Errorf("me.ai = %+v", me.AI)
	}
	var sug map[string]any
	if got := e.call(root, "POST", "/api/v1/parsers/suggest", lines, &sug, nil); got != 200 || sug["matched"] != float64(2) {
		t.Errorf("suggest = %d %+v", got, sug)
	}
	// The switch on the Integrations page turns suggestions off and on.
	if got := e.call(root, "POST", "/api/v1/integrations/ai/enabled", map[string]bool{"enabled": false}, nil, nil); got != 200 {
		t.Fatal("switch off")
	}
	if got := e.call(root, "POST", "/api/v1/parsers/suggest", lines, nil, nil); got != 404 {
		t.Errorf("suggest when off = %d", got)
	}
	if e.call(sam, "GET", "/api/v1/me", nil, &me, nil); me.AI.Enabled {
		t.Error("me.ai still on")
	}
}
