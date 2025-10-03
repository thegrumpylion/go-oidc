package device

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

const (
	// DefaultUserCodeCharset defines the set of characters to be used for generating the user_code.
	// This set consists of 20 uppercase consonants, chosen to avoid visual ambiguity.
	// https://datatracker.ietf.org/doc/html/rfc8628#section-6.1
	DefaultUserCodeCharset = "BCDFGHJKLMNPQRSTVWXZ"
	// DefaultUserCodeLength defines the fixed length of the generated user_code.
	DefaultUserCodeLength = 8
)

// generateUserCode creates a user-friendly code of a fixed length from a specific character set.
// The code is 8 characters long and uses uppercase consonants designed to be non-confusable.
// It uses crypto/rand for selecting characters, ensuring unpredictability.
// https://datatracker.ietf.org/doc/html/rfc8628#section-6.1
func generateUserCode(charSet string, codeLen int) (string, error) {
	var sb strings.Builder
	sb.Grow(codeLen)

	// The maximum value for our random number generator is the length of the character set.
	charSetMaxIndex := big.NewInt(int64(len(DefaultUserCodeCharset)))

	for range codeLen {
		// Generate a cryptographically secure random index within the bounds of the character set.
		randomIndexBig, err := rand.Int(rand.Reader, charSetMaxIndex)
		if err != nil {
			// If generating a random number fails, propagate the error.
			return "", fmt.Errorf("failed to generate random index for user code: %w", err)
		}
		// Get the integer value of the random big.Int (it will be small).
		randomIndex := randomIndexBig.Int64()

		// Append the character at the random index from our character set.
		sb.WriteByte(charSet[randomIndex])
	}

	return sb.String(), nil
}

func generateDeviceCode() string {
	numBytes := 32
	randomBytes := make([]byte, numBytes)

	rand.Read(randomBytes)
	deviceCode := base64.RawURLEncoding.EncodeToString(randomBytes)

	return deviceCode
}
