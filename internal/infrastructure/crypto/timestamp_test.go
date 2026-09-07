package crypto

import (
	"testing"
	"time"
)

func TestValidateTimestampValid(t *testing.T) {
	now := time.Now()
	ts := now.Format(time.RFC3339)
	err := ValidateTimestamp(ts, 300, now)
	if err != nil {
		t.Fatalf("current timestamp should be valid: %v", err)
	}
}

func TestValidateTimestampWithinSkew(t *testing.T) {
	now := time.Now()
	ts := now.Add(-200 * time.Second).Format(time.RFC3339)
	err := ValidateTimestamp(ts, 300, now)
	if err != nil {
		t.Fatalf("timestamp within skew should be valid: %v", err)
	}
}

func TestValidateTimestampOutOfWindow(t *testing.T) {
	now := time.Now()
	ts := now.Add(-600 * time.Second).Format(time.RFC3339)
	err := ValidateTimestamp(ts, 300, now)
	if err == nil {
		t.Fatal("timestamp outside skew should fail")
	}
}

func TestValidateTimestampFuture(t *testing.T) {
	now := time.Now()
	ts := now.Add(600 * time.Second).Format(time.RFC3339)
	err := ValidateTimestamp(ts, 300, now)
	if err == nil {
		t.Fatal("future timestamp outside skew should fail")
	}
}

func TestValidateTimestampInvalidFormat(t *testing.T) {
	now := time.Now()
	err := ValidateTimestamp("not-a-timestamp", 300, now)
	if err == nil {
		t.Fatal("invalid format should fail")
	}
}

func TestValidateTimestampZuluFormat(t *testing.T) {
	now := time.Now()
	ts := now.UTC().Format(time.RFC3339)
	err := ValidateTimestamp(ts, 300, now)
	if err != nil {
		t.Fatalf("Zulu format should be valid: %v", err)
	}
}

func TestValidateTimestampNoTimezone(t *testing.T) {
	now := time.Now().UTC()
	ts := now.Format("2006-01-02T15:04:05")
	err := ValidateTimestamp(ts, 300, now)
	if err != nil {
		t.Fatalf("timestamp without timezone (assumed UTC) should be valid: %v", err)
	}
}
