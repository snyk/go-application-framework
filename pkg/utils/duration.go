package utils

import (
	"fmt"
	"math"
	"time"
)

// HumanDuration formats a duration into a human-readable string,
// picking the most appropriate unit (seconds, minutes, or hours+minutes).
func HumanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(math.Ceil(d.Seconds())))
	case d < time.Hour:
		return fmt.Sprintf("~%d min", int(math.Ceil(d.Minutes())))
	default:
		hours := int(d.Hours())
		mins := int(math.Ceil((d - time.Duration(hours)*time.Hour).Minutes()))
		if mins > 0 {
			return fmt.Sprintf("~%d h %d min", hours, mins)
		}
		return fmt.Sprintf("~%d h", hours)
	}
}
