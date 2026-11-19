package enrichmentrelease

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

const maxGeneration = int64(1<<63 - 1)

var errInvalidRelease = errors.New("invalid release data")

func invalid(reason string) error {
	return fmt.Errorf("release %s: %w", reason, errInvalidRelease)
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return false
			}
		} else if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

func lowerHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range s {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

func validDigest(s string) bool {
	return len(s) == 71 && s[:7] == "sha256:" && lowerHex(s[7:])
}

func validReceipt(s string) bool {
	const prefix = "refresh-success-v1:sha256:"
	return len(s) == len(prefix)+64 && s[:len(prefix)] == prefix && lowerHex(s[len(prefix):])
}

func payloadDigest(data []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}
