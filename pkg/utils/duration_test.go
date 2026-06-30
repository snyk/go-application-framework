package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHumanDuration(t *testing.T) {
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
		{"sub-second rounds up", 500 * time.Millisecond, "1 s"},
		{"exactly 1 minute", 1 * time.Minute, "~1 min"},
		{"5 minutes", 5 * time.Minute, "~5 min"},
		{"90 seconds rounds to 2 min", 90 * time.Second, "~2 min"},
		{"59 minutes", 59 * time.Minute, "~59 min"},
		{"exactly 1 hour", 1 * time.Hour, "~1 h"},
		{"1 hour 30 min", 90 * time.Minute, "~1 h 30 min"},
		{"2 hours", 2 * time.Hour, "~2 h"},
		{"2 hours 15 min", 2*time.Hour + 15*time.Minute, "~2 h 15 min"},
		{"24 hours", 24 * time.Hour, "~24 h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, HumanDuration(tt.duration))
		})
	}
}
