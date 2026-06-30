package humanfmt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{"zero", 0, "0 s"},
		{"1 second", 1 * time.Second, "1 s"},
		{"5 seconds", 5 * time.Second, "5 s"},
		{"30 seconds", 30 * time.Second, "30 s"},
		{"59 seconds", 59 * time.Second, "59 s"},
		{"sub-second rounds to nearest", 500 * time.Millisecond, "1 s"},
		{"61 seconds stays in seconds", 61 * time.Second, "61 s"},
		{"89 seconds stays in seconds", 89 * time.Second, "89 s"},
		{"90 seconds switches to minutes", 90 * time.Second, "~2 min"},
		{"exactly 2 minutes", 2 * time.Minute, "~2 min"},
		{"5 minutes", 5 * time.Minute, "~5 min"},
		{"5m20s rounds down", 5*time.Minute + 20*time.Second, "~5 min"},
		{"5m40s rounds up", 5*time.Minute + 40*time.Second, "~6 min"},
		{"59 minutes", 59 * time.Minute, "~59 min"},
		{"59m20s rounds down", 59*time.Minute + 20*time.Second, "~59 min"},
		{"exactly 1 hour", 1 * time.Hour, "~1 h"},
		{"1h20m rounds down", 1*time.Hour + 20*time.Minute, "~1 h"},
		{"1h40m rounds up", 1*time.Hour + 40*time.Minute, "~2 h"},
		{"2 hours", 2 * time.Hour, "~2 h"},
		{"24 hours", 24 * time.Hour, "~24 h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, Duration(tt.duration))
		})
	}
}
