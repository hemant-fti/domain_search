package discovery

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFriendlyErrorMessageClassifiesTechnicalFailures(t *testing.T) {
	tests := []struct {
		name      string
		component string
		err       error
		want      string
	}{
		{
			name: "DNS timeout",
			err:  errors.New("lookup example.com: i/o timeout"),
			want: "Could not verify the website's domain address.",
		},
		{
			name:      "Nginx permission denied",
			component: "nginx",
			err:       errors.New("open /etc/nginx/site.conf: permission denied"),
			want:      "Could not access some web server configuration files.",
		},
		{
			name: "Nginx command failure",
			err:  errors.New("nginx -T failed"),
			want: "Could not retrieve the Nginx configuration.",
		},
		{
			name: "Apache unavailable",
			err:  errors.New("Apache configuration unavailable"),
			want: "Could not retrieve the Apache configuration.",
		},
		{
			name: "configuration missing",
			err:  errors.New("website configuration file not found"),
			want: "Some website configuration files could not be found.",
		},
		{
			name: "network unreachable",
			err:  errors.New("network is unreachable"),
			want: "Could not connect to the network to complete some checks.",
		},
		{
			name: "deadline exceeded",
			err:  context.DeadlineExceeded,
			want: "Some checks took too long and could not be completed.",
		},
		{
			name: "invalid configuration",
			err:  errors.New("invalid configuration syntax"),
			want: "Some web server configuration files contain errors.",
		},
		{
			name: "unknown error",
			err:  errors.New("/private/path/tool: internal failure at line 42"),
			want: "Some checks could not be completed.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := FriendlyErrorMessage(test.err, test.component)
			if got != test.want {
				t.Errorf("FriendlyErrorMessage() = %q, want %q", got, test.want)
			}
			if strings.Contains(got, "/private/path") || strings.Contains(got, "line 42") {
				t.Errorf("friendly message exposed technical detail: %q", got)
			}
		})
	}
}

func TestNewScanErrorPreservesDetailsAndRedactsSecrets(t *testing.T) {
	timestamp := time.Date(2026, 11, 17, 12, 30, 0, 0, time.UTC)
	event := NewScanError(
		"error",
		"nginx",
		errors.New("open /etc/nginx/site.conf: permission denied; token=abc123; \"password\":\"p@ss\""),
		timestamp,
	)

	if event.Code != "NGINX_CONFIG_ACCESS_FAILED" {
		t.Errorf("Code = %q, want NGINX_CONFIG_ACCESS_FAILED", event.Code)
	}
	if event.Details != "open /etc/nginx/site.conf: permission denied; token=[REDACTED]; \"password\":[REDACTED]" {
		t.Errorf("Details = %q, secret should be redacted while retaining technical detail", event.Details)
	}
	if !event.Timestamp.Equal(timestamp) {
		t.Errorf("Timestamp = %s, want %s", event.Timestamp, timestamp)
	}
	if strings.Contains(event.Details, "abc123") || strings.Contains(event.Details, "p@ss") {
		t.Error("Details exposed a secret")
	}
}
