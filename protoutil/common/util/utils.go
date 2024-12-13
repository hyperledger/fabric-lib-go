package util

// ConcatenateBytes is useful for combining multiple arrays of bytes, especially for
// signatures or digests over multiple fields
// This way is more efficient in speed
func ConcatenateBytes(data ...[]byte) []byte {
	finalLength := 0
	for _, slice := range data {
		finalLength += len(slice)
	}
	result := make([]byte, finalLength)
	last := 0
	for _, slice := range data {
		last += copy(result[last:], slice)
	}
	return result
}
