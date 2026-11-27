package security

import (
	"slices"
	"strings"
	"testing"
)

func TestRedactText(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"key=value", "token=abc123; next", "token=[REDACTED]; next"},
		{"json", `"password":"p@ss"`, `"password":[REDACTED]`},
		{"is form", "the secret is hunter2", "the secret is [REDACTED]"},
		{"env var", "DB_PASSWORD=hunter2", "DB_PASSWORD=[REDACTED]"},
		{"url credentials", "dial https://user:pw@example.com/x", "dial https://user:[REDACTED]@example.com/x"},
		{"authorization header", "Authorization: Bearer xyz", "Authorization: [REDACTED]"},
		{"private key", "a -----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY----- b", "a [REDACTED PRIVATE KEY] b"},
		{"no secret", "open /etc/nginx/site.conf: permission denied", "open /etc/nginx/site.conf: permission denied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactText(tt.in); got != tt.want {
				t.Errorf("RedactText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedactArgs(t *testing.T) {
	in := []string{"scan", "--password", "s3cret", "--api-key=abc", "--timeout", "5s"}
	want := []string{"scan", "--password", "[REDACTED]", "--api-key=[REDACTED]", "--timeout", "5s"}
	got := RedactArgs(in)
	if !slices.Equal(got, want) {
		t.Errorf("RedactArgs = %v, want %v", got, want)
	}
	if strings.Join(in, " ") != "scan --password s3cret --api-key=abc --timeout 5s" {
		t.Error("RedactArgs modified its input")
	}
}
