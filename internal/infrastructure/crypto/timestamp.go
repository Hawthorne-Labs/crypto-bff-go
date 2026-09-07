package crypto

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/Hawthorne-Labs/crypto-bff-go/internal/domain/fle"
)

// ValidateTimestamp checks that the timestamp is within the allowed skew.
func ValidateTimestamp(timestamp string, skewSeconds int, now time.Time) error {
	provided, err := parseTimestamp(timestamp)
	if err != nil {
		return fmt.Errorf("%w: invalid timestamp format", fle.ErrTimestampOutOfWindow)
	}

	delta := math.Abs(now.Sub(provided).Seconds())
	if delta > float64(skewSeconds) {
		return fmt.Errorf("%w: timestamp drift %.0fs exceeds %ds", fle.ErrTimestampOutOfWindow, delta, skewSeconds)
	}
	return nil
}

func parseTimestamp(value string) (time.Time, error) {
	// Handle Z suffix
	if strings.HasSuffix(value, "Z") {
		value = value[:len(value)-1] + "+00:00"
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		// Try without timezone (assume UTC)
		t, err = time.Parse("2006-01-02T15:04:05", value)
		if err != nil {
			return time.Time{}, err
		}
		return t.UTC(), nil
	}
	return t.UTC(), nil
}
