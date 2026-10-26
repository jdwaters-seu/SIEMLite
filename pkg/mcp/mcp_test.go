package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func testServer() *Server {
	echo := func(ctx context.Context, args json.RawMessage) (Result, error) {
		var a struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return Result{}, errors.New("text must be a string")
		}
		return Result{Text: "echo: " + a.Text}, nil
	}
	return &Server{Name: "test", Version: "1", Instructions: "be careful", Tools: []Tool{
		{Name: "look", Description: "reads", Schema: map[string]any{"type": "object"}, Min: LevelRead, ReadOnly: true, Run: echo},
		{Name: "change", Description: "writes", Schema: map[string]any{"type": "object"}, Min: LevelAnalyst, Run: echo},
		{Name: "remove", Description: "deletes", Schema: map[string]any{"type": "object"}, Min: LevelAdmin, Destructive: true, Run: echo},
		{Name: "boom", Description: "panics", Schema: map[string]any{"type": "object"}, Min: LevelRead, Run: func(context.Context, json.RawMessage) (Result, error) { panic("x") }},
	}}
}

func call(t *testing.T, s *Server, level int, body string) (int, map[string]any) {
	t.Helper()
	status, out := s.Handle(context.Background(), level, []byte(body))
	var m map[string]any
	if len(out) > 0 {
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("not JSON: %s", out)
		}
	}
	return status, m
}

func TestInitializeNegotiatesVersion(t *testing.T) {
	s := testServer()
	for _, tc := range []struct{ asks, want string }{{"2025-03-26", "2025-03-26"}, {"2024-11-05", "2024-11-05"}, {"1999-01-01", "2025-06-18"}, {"", "2025-06-18"}} {
		status, m := call(t, s, LevelRead, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+tc.asks+`"}}`)
		res, _ := m["result"].(map[string]any)
		if status != 200 || res["protocolVersion"] != tc.want || res["instructions"] != "be careful" {
			t.Errorf("asked %q: %d %v", tc.asks, status, m)
		}
		if info, _ := res["serverInfo"].(map[string]any); info["name"] != "test" {
			t.Errorf("serverInfo = %v", res["serverInfo"])
		}
	}
}

func names(m map[string]any) []string {
	var out []string
	for _, x := range m["result"].(map[string]any)["tools"].([]any) {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	return out
}

func TestToolsListShowsOnlyWhatTheLevelMayUse(t *testing.T) {
	s := testServer()
	for level, want := range map[int]string{LevelRead: "look boom", LevelAnalyst: "look change boom", LevelAdmin: "look change remove boom"} {
		_, m := call(t, s, level, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		if got := strings.Join(names(m), " "); got != want {
			t.Errorf("level %d lists %q, want %q", level, got, want)
		}
	}
	_, m := call(t, s, LevelAdmin, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	for _, x := range m["result"].(map[string]any)["tools"].([]any) {
		tool := x.(map[string]any)
		ann := tool["annotations"].(map[string]any)
		switch tool["name"] {
		case "look":
			if ann["readOnlyHint"] != true || ann["destructiveHint"] != false {
				t.Errorf("look annotations = %v", ann)
			}
		case "remove":
			if ann["destructiveHint"] != true {
				t.Errorf("remove annotations = %v", ann)
			}
		}
	}
}

func text(m map[string]any) (string, bool) {
	res := m["result"].(map[string]any)
	return res["content"].([]any)[0].(map[string]any)["text"].(string), res["isError"].(bool)
}

func TestToolCalls(t *testing.T) {
	s := testServer()
	_, m := call(t, s, LevelRead, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"look","arguments":{"text":"hi"}}}`)
	if got, isErr := text(m); got != "echo: hi" || isErr {
		t.Errorf("call = %q error=%v", got, isErr)
	}
	// No arguments at all is an empty object.
	_, m = call(t, s, LevelRead, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"look"}}`)
	if got, isErr := text(m); got != "echo: " || isErr {
		t.Errorf("no arguments = %q error=%v", got, isErr)
	}
	// A tool's mistake is text for the model, not a protocol error.
	_, m = call(t, s, LevelRead, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"look","arguments":{"text":5}}}`)
	if got, isErr := text(m); got != "text must be a string" || !isErr {
		t.Errorf("bad arguments = %q error=%v", got, isErr)
	}
	// A level too low is refused with a reason, even if the name is guessed.
	_, m = call(t, s, LevelRead, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remove","arguments":{}}}`)
	if got, isErr := text(m); !isErr || !strings.Contains(got, "read-only") || !strings.Contains(got, "admin") {
		t.Errorf("refused = %q error=%v", got, isErr)
	}
	// A panic in a tool doesn't take the server down.
	_, m = call(t, s, LevelRead, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"boom"}}`)
	if _, isErr := text(m); !isErr {
		t.Errorf("a panic wasn't reported as an error: %v", m)
	}
	// An unknown tool is a protocol error.
	_, m = call(t, s, LevelAdmin, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope"}}`)
	if e, _ := m["error"].(map[string]any); e == nil || e["code"] != float64(-32602) {
		t.Errorf("unknown tool = %v", m)
	}
}

func TestProtocolEdges(t *testing.T) {
	s := testServer()
	// Notifications and replies get no answer.
	for _, body := range []string{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, `{"jsonrpc":"2.0","id":9,"result":{}}`} {
		if status, out := s.Handle(context.Background(), LevelRead, []byte(body)); status != http.StatusAccepted || len(out) != 0 {
			t.Errorf("%s -> %d %q", body, status, out)
		}
	}
	// Ping, an unknown method, garbage and a request without a method.
	_, m := call(t, s, LevelRead, `{"jsonrpc":"2.0","id":"a","method":"ping"}`)
	if m["id"] != "a" || m["result"] == nil {
		t.Errorf("ping = %v", m)
	}
	_, m = call(t, s, LevelRead, `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`)
	if e, _ := m["error"].(map[string]any); e == nil || e["code"] != float64(-32601) {
		t.Errorf("unknown method = %v", m)
	}
	if status, _ := call(t, s, LevelRead, `not json`); status != http.StatusBadRequest {
		t.Errorf("garbage = %d", status)
	}
	if status, _ := call(t, s, LevelRead, `{"jsonrpc":"2.0","id":4}`); status != http.StatusOK {
		t.Errorf("no method = %d", status)
	}
	// A batch answers each request and skips notifications.
	status, out := s.Handle(context.Background(), LevelRead, []byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`))
	var batch []map[string]any
	if json.Unmarshal(out, &batch); status != 200 || len(batch) != 2 {
		t.Errorf("batch = %d %s", status, out)
	}
	if status, out := s.Handle(context.Background(), LevelRead, []byte(`[{"jsonrpc":"2.0","method":"notifications/initialized"}]`)); status != http.StatusAccepted || len(out) != 0 {
		t.Errorf("batch of notifications = %d %q", status, out)
	}
}

func TestLongAnswersAreCut(t *testing.T) {
	s := &Server{Name: "t", Tools: []Tool{{Name: "big", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage) (Result, error) {
		return Result{Text: strings.Repeat("line of text\n", 50_000)}, nil
	}}}}
	_, m := call(t, s, LevelRead, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"big"}}`)
	got, _ := text(m)
	if len(got) > maxResultBytes+200 || !strings.Contains(got, "cut at 200 KB") {
		t.Errorf("answer is %d bytes", len(got))
	}
}
