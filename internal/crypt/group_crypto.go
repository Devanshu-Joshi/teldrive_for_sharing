package crypt

import (
	"crypto/sha256"
	"encoding/hex"
)

// ComputeGroupHash calculates SHA256(cryptoFingerprint + groupSecret).
// This generates the cryptographic double-hash used to verify that the host 
// and members share the exact same encryption keys and group secret.
func ComputeGroupHash(cryptoFingerprint string, groupSecret string) string {
	hasher := sha256.New()
	hasher.Write([]byte(cryptoFingerprint + groupSecret))
	return hex.EncodeToString(hasher.Sum(nil))
}
