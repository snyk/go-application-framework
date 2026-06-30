package humanfmt

import (
	"fmt"
	"math"
	"time"
)

// Duration formats a duration into a human-readable string,
// picking the most appropriate unit (seconds, minutes, or hours).
func Duration(d time.Duration) string {
	switch {
	case d < 90*time.Second:
		return fmt.Sprintf("%d s", int(math.Round(d.Seconds())))
	case d < time.Hour:
		return fmt.Sprintf("~%d min", int(math.Round(d.Minutes())))
	default:
		hours := int(math.Round(d.Hours()))
		return fmt.Sprintf("~%d h", hours)
	}
}
