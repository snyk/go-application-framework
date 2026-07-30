package llm

import (
	"strings"
	"testing"
)

func TestNormalizeOpenAIBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr string // non-empty: expect an error containing this substring
	}{
		{"bare host gets /v1", "https://proxy.example.com", "https://proxy.example.com/v1", ""},
		{"trailing slash", "https://proxy.example.com/", "https://proxy.example.com/v1", ""},
		{"already has /v1", "https://proxy.example.com/v1", "https://proxy.example.com/v1", ""},
		{"/v1 with trailing slash", "https://proxy.example.com/v1/", "https://proxy.example.com/v1", ""},
		{"full endpoint pasted", "https://proxy.example.com/v1/chat/completions", "https://proxy.example.com/v1", ""},
		{"endpoint without v1", "https://proxy.example.com/chat/completions", "https://proxy.example.com/v1", ""},
		{"custom gateway prefix left intact", "https://gw.example.com/llm", "https://gw.example.com/llm", ""},
		{"whitespace trimmed", "  https://proxy.example.com  ", "https://proxy.example.com/v1", ""},

		// localhost is allowed over HTTP for local development
		{"localhost http allowed", "http://localhost:4000", "http://localhost:4000/v1", ""},
		{"127.0.0.1 http allowed", "http://127.0.0.1:8080/v1", "http://127.0.0.1:8080/v1", ""},

		// plain HTTP to a remote host must be rejected
		{"http remote rejected", "http://proxy.example.com", "", "must use HTTPS"},
		{"http remote with path rejected", "http://proxy.example.com/v1", "", "must use HTTPS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeOpenAIBaseURL(tc.in)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("normalizeOpenAIBaseURL(%q): expected error containing %q, got nil", tc.in, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("normalizeOpenAIBaseURL(%q): error = %q, want substring %q", tc.in, err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeOpenAIBaseURL(%q): unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("normalizeOpenAIBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeAnthropicBaseURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty (default applies)", "", ""},
		{"bare host gets /v1", "https://proxy.example.com", "https://proxy.example.com/v1"},
		{"trailing slash", "https://proxy.example.com/", "https://proxy.example.com/v1"},
		{"already has /v1", "https://proxy.example.com/v1", "https://proxy.example.com/v1"},
		{"/v1 with trailing slash", "https://proxy.example.com/v1/", "https://proxy.example.com/v1"},
		{"full endpoint pasted", "https://proxy.example.com/v1/messages", "https://proxy.example.com/v1"},
		{"endpoint without v1", "https://proxy.example.com/messages", "https://proxy.example.com/v1"},
		{"custom gateway prefix left intact", "https://gw.example.com/anthropic", "https://gw.example.com/anthropic"},
		{"whitespace trimmed", "  https://proxy.example.com  ", "https://proxy.example.com/v1"},
		// HTTP is allowed (keyless internal gateway, no key to leak).
		{"internal http allowed", "http://gateway.internal", "http://gateway.internal/v1"},
		{"http with port and path intact", "http://gateway.internal:8080/llm", "http://gateway.internal:8080/llm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeAnthropicBaseURL(tc.in); got != tc.want {
				t.Errorf("normalizeAnthropicBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
