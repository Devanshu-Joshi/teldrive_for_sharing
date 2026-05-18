package utils

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// IsVirtualID checks if an ID represents a virtual folder.
func IsVirtualID(id string) bool {
	return strings.HasPrefix(id, "virtual_")
}

// ParseVirtualID extracts the user ID from a virtual folder ID string.
func ParseVirtualID(id string) (int64, error) {
	if !IsVirtualID(id) {
		return 0, strconv.ErrSyntax
	}
	userIdStr := strings.TrimPrefix(id, "virtual_")
	val, err := strconv.ParseInt(userIdStr, 10, 64)
	if err != nil {
		return 0, err
	}
	if val <= 0 {
		return 0, strconv.ErrSyntax
	}
	// Check for strict canonical representation to reject "+1", "01", " 1", etc.
	if strconv.FormatInt(val, 10) != userIdStr {
		return 0, strconv.ErrSyntax
	}
	return val, nil
}

// GenerateRandomSecret generates a cryptographically secure random secret.
func GenerateRandomSecret(length int) string {
	bytes := make([]byte, length/2)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func CamelToSnake(input string) string {
	re := regexp.MustCompile("([a-z0-9])([A-Z])")
	snake := re.ReplaceAllString(input, "${1}_${2}")
	return strings.ToLower(snake)
}

func Ptr[T any](t T) *T {
	return &t
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func ExecutableDir() string {
	path, _ := os.Executable()
	return filepath.Dir(path)
}

func Filter[T any](slice []T, predicate func(T) bool) []T {
	var result []T
	for _, v := range slice {
		if predicate(v) {
			result = append(result, v)
		}
	}
	return result
}

func Map[T any, U any](slice []T, mapper func(T) U) []U {
	var result []U
	for _, v := range slice {
		result = append(result, mapper(v))
	}
	return result
}

func Find[T any](slice []T, predicate func(T) bool) (T, bool) {
	for _, v := range slice {
		if predicate(v) {
			return v, true
		}
	}
	var zero T
	return zero, false
}
