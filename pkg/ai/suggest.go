// Package ai suggests parsers from sample log lines: the AI Parsers
// integration. The model runs on this server with Ollama (https://ollama.com),
// where nothing leaves your network, or in the cloud through OpenRouter
// (https://openrouter.ai), with addresses replaced before lines are sent.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"siemlite/pkg/parser"
)

// Suggestion is a proposed parser and how well it fits the samples.
type Suggestion struct {
	Definition parser.Definition `json:"definition"`
	Matched    int               `json:"matched"`
	Total      int               `json:"total"`
	Attempts   int               `json:"attempts"`
}

// Suggest proposes a parser for the sample lines. Work a program can do
// reliably is done here, not by the model: syslog headers are detected and
// removed, and JSON or key=value lines are recognised, so the model only
// writes a pattern for free text, or maps fields and picks severity.
func suggest(ctx context.Context, ch chatter, log *slog.Logger, lines []string) (*Suggestion, error) {
	var samples []string
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" && len(samples) < 12 {
			if len(l) > 600 {
				l = l[:600]
			}
			samples = append(samples, l)
		}
	}
	if len(samples) == 0 {
		return nil, errors.New("add some sample lines first")
	}

	bodies, strip := syslogBodies(samples)
	format := detectFormat(bodies)
	base := parser.Definition{Name: "Suggested parser", Format: format, StripSyslog: strip, Category: 6, Severity: parser.SeverityRule{From: "auto"}}

	if format != parser.FormatPattern {
		names := fieldNames(base, bodies)
		prompt := "These log lines are " + map[string]string{"json": "JSON objects", "kv": "key=value pairs"}[format] +
			". Their fields are: " + strings.Join(names, ", ") + "\n\nSample lines:\n" + strings.Join(bodies, "\n")
		def, _, err := ask(ctx, ch, []map[string]string{{"role": "system", "content": mappingPrompt}, {"role": "user", "content": prompt}}, mappingSchema)
		// SIEMLite's own draft is the base; the model adds what it missed.
		draft := parser.Draft(samples)
		base.Fields, base.Severity, base.Category = draft.Fields, draft.Severity, draft.Category
		if errors.Is(err, errCouldntMask) {
			return nil, err
		}
		if err != nil {
			log.Warn("AI field mapping failed; using SIEMLite's own draft", "err", err)
		} else {
			taken := map[string]bool{}
			for _, t := range base.Fields {
				taken[t] = true
			}
			for k, v := range keepKnown(def.Fields, names) {
				if base.Fields[k] == "" && !taken[v] {
					base.Fields[k], taken[v] = v, true
				}
			}
			if base.Severity.From == "auto" && !taken["severity"] {
				base.Severity = def.Severity
			}
			if base.Category == 6 && def.Category != 0 {
				base.Category = def.Category
			}
		}
		s, _ := score(base, samples)
		if s.Matched < s.Total || compileErr(base) != nil {
			// The model's additions broke the parser: keep the draft alone.
			base.Fields, base.Severity, base.Category = draft.Fields, draft.Severity, draft.Category
			s, _ = score(base, samples)
		}
		s.Attempts = 1
		return s, nil
	}

	// Free text: SIEMLite drafts a pattern that matches every line; the model
	// improves its names and chooses severity and category. Its pattern is
	// used only if it still matches every line.
	draft := base
	draft.Pattern = parser.DraftPattern(bodies)
	best, _ := score(draft, samples)
	best.Attempts = 0
	note := ""
	if strip {
		note = "The syslog header has already been removed from these lines.\n"
	}
	msgs := []map[string]string{
		{"role": "system", "content": systemPrompt},
		{"role": "user", "content": note + "Lines:\n" + strings.Join(bodies, "\n") +
			"\n\nThis pattern already matches every line:\n" + draft.Pattern +
			"\n\nImprove it: rename placeholders to say what they hold (use event field names where they fit, " +
			"e.g. a user name placeholder should be {user}), split a placeholder only where every line allows it, " +
			"and choose severity and category. It must still match every line."},
	}
	names := placeholders(draft.Pattern)
	for attempt := 1; attempt <= 2; attempt++ {
		def, raw, err := ask(ctx, ch, msgs, schema)
		if errors.Is(err, errCouldntMask) {
			return nil, err
		}
		if err != nil {
			log.Warn("AI parser suggestion attempt failed", "attempt", attempt, "err", err)
			break
		}
		def.Format, def.StripSyslog, def.Name = parser.FormatPattern, strip, base.Name
		if def.Category == 0 {
			def.Category = 6
		}
		s, _ := score(def, samples)
		s.Attempts = attempt
		if s.Matched == s.Total {
			return s, nil
		}
		// Keep the draft, but take the model's severity and category when
		// they make sense for the draft's fields.
		if attempt == 1 {
			if def.Severity.From != "field" || contains(names, def.Severity.Field) {
				withMeta := draft
				withMeta.Severity, withMeta.Category = def.Severity, def.Category
				if ms, _ := score(withMeta, samples); ms.Matched == ms.Total {
					best = ms
					best.Attempts = attempt
				}
			}
		}
		msgs = append(msgs,
			map[string]string{"role": "assistant", "content": raw},
			map[string]string{"role": "user", "content": feedback(def, bodies)})
	}
	return best, nil
}

func placeholders(pattern string) []string {
	_, names, _ := parser.CompilePattern(pattern)
	return names
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// syslogBodies strips syslog headers when most lines have one.
func syslogBodies(samples []string) ([]string, bool) {
	bodies := make([]string, len(samples))
	n := 0
	for i, l := range samples {
		b, ok := parser.SyslogBody(l)
		bodies[i] = b
		if ok {
			n++
		}
	}
	if n*2 < len(samples) {
		return samples, false
	}
	return bodies, true
}

var kvLike = regexp.MustCompile(`(^|\s)[A-Za-z_][A-Za-z0-9_.-]*=`)

// detectFormat recognises JSON objects and key=value lines.
func detectFormat(bodies []string) string {
	jsonN, kvN := 0, 0
	for _, b := range bodies {
		var obj map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(b)), &obj) == nil {
			jsonN++
		}
		if len(kvLike.FindAllString(b, -1)) >= 3 {
			kvN++
		}
	}
	switch {
	case jsonN == len(bodies):
		return parser.FormatJSON
	case kvN == len(bodies):
		return parser.FormatKV
	}
	return parser.FormatPattern
}

func fieldNames(def parser.Definition, bodies []string) []string {
	p, err := parser.Compile(def)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	for _, b := range bodies {
		f, err := p.Fields(b)
		if err != nil {
			continue
		}
		for k := range f {
			if !seen[k] {
				seen[k] = true
				names = append(names, k)
			}
		}
	}
	sort.Strings(names)
	return names
}

// keepKnown drops mappings for fields the lines don't have.
func keepKnown(fields map[string]string, names []string) map[string]string {
	ok := map[string]bool{}
	for _, n := range names {
		ok[n] = true
	}
	out := map[string]string{}
	for k, v := range fields {
		if ok[k] && v != "" {
			out[k] = v
		}
	}
	return out
}

func compileErr(def parser.Definition) error { _, err := parser.Compile(def); return err }

// feedback tells the model exactly where its pattern went wrong.
func feedback(def parser.Definition, bodies []string) string {
	if _, _, err := parser.CompilePattern(def.Pattern); err != nil {
		return "That pattern is invalid: " + err.Error() + ". Write a corrected pattern."
	}
	var sb strings.Builder
	sb.WriteString("The pattern doesn't match every line. Problems:\n")
	n := 0
	for _, b := range bodies {
		matched, next, ok := parser.Explain(def.Pattern, b)
		if ok || n == 4 {
			continue
		}
		n++
		fmt.Fprintf(&sb, "- Line: %s\n  The pattern matches up to %q but the line doesn't continue with %q.\n", b, matched, next)
	}
	sb.WriteString("Every literal character must appear in every line. Use a {placeholder} for anything that varies. Write a corrected pattern.")
	return sb.String()
}

func ask(ctx context.Context, ch chatter, msgs []map[string]string, format any) (parser.Definition, string, error) {
	content, err := ch.chat(ctx, msgs, format)
	if err != nil {
		return parser.Definition{}, "", err
	}
	var def parser.Definition
	if err := json.Unmarshal([]byte(content), &def); err != nil {
		return parser.Definition{}, "", fmt.Errorf("the model's answer wasn't a parser: %w", err)
	}
	def.Name = "Suggested parser"
	return def, content, nil
}

// score compiles def and tests it on the samples.
func score(def parser.Definition, samples []string) (*Suggestion, string) {
	s := &Suggestion{Definition: def, Total: len(samples)}
	p, err := parser.Compile(def)
	if err != nil {
		return s, "the parser is invalid: " + err.Error()
	}
	for _, l := range samples {
		if _, err := p.Parse(l, parser.Defaults{}); err == nil {
			s.Matched++
		}
	}
	return s, ""
}

var severitySchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"from":  map[string]any{"type": "string", "enum": []string{"auto", "fixed", "field"}},
		"fixed": map[string]any{"type": "integer", "minimum": 0, "maximum": 6},
		"field": map[string]any{"type": "string"},
		"rules": map[string]any{"type": "array", "items": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"match":    map[string]any{"type": "string"},
				"severity": map[string]any{"type": "integer", "minimum": 0, "maximum": 6},
			},
			"required": []string{"match", "severity"},
		}},
	},
	"required": []string{"from"},
}

var fieldsSchema = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string", "enum": append([]string{""}, parser.Targets...)}}

// schema is the answer for free-text lines: a pattern.
var schema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"pattern":  map[string]any{"type": "string"},
		"fields":   fieldsSchema,
		"category": map[string]any{"type": "integer", "minimum": 1, "maximum": 8},
		"severity": severitySchema,
	},
	"required": []string{"pattern", "severity", "category"},
}

// mappingSchema is the answer for JSON and key=value lines.
var mappingSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"fields":   fieldsSchema,
		"category": map[string]any{"type": "integer", "minimum": 1, "maximum": 8},
		"severity": severitySchema,
	},
	"required": []string{"fields", "severity", "category"},
}

const targetsHelp = `Event fields: time, src_ip, src_port, dst_ip, dst_port, user, host, app, message, severity.

"severity": use {"from":"auto"} unless a field clearly decides it, like an HTTP status, a result or a firewall action;
then use {"from":"field","field":"<field>","rules":[{"match":"<regex>","severity":<n>}, ...]} with a final {"match":".","severity":1}.
Severities: 1 informational, 2 low, 3 medium, 4 high, 5 critical.

"category": 3 for logins and authentication, 4 for network and web traffic, 1 for system and process activity,
2 for security findings, 6 for application logs.`

const systemPrompt = `You write a pattern that matches every given log line. Reply with JSON only.

A pattern is one line written out with {name} placeholders where the values change between lines.
- Text outside placeholders must appear in every line exactly. A single space matches any run of spaces.
- {name} matches as little text as possible, or the rest of the line when it is last.
- {} skips text you don't need. {name:REGEX} uses your own regex, e.g. {status:\d+} or {level:[A-Z]+}.
- Where lines differ in wording (different messages), use a placeholder, usually {message} at the end.

Name placeholders after what they hold. These names fill event fields directly: time, src_ip, src_port, dst_ip,
dst_port, user, host, app, message, severity. Give other values their own names (method, status, path, action...).
"fields" maps a placeholder to an event field only when its name differs, e.g. {"client": "src_ip"}; usually {}.

` + targetsHelp + `

Example. Lines:
2026-10-03 10:17:12 WARN  [auth] login failed user=bob from 192.0.2.10
2026-10-03 10:18:01 INFO  [billing] invoice sent user=alice from 10.0.0.41
Answer:
{"pattern":"{time} {level} [{component}] {message} user={user} from {src_ip}","fields":{"level":"severity"},"category":6,"severity":{"from":"auto"}}`

const mappingPrompt = `You map the fields of structured log lines to event fields. Reply with JSON only.

"fields" maps a field name, exactly as listed, to an event field. Only map fields whose meaning is clear, e.g.
{"actor.ip": "src_ip", "actor.name": "user", "ts": "time", "outcome": ""}. Leave other fields out.

` + targetsHelp
