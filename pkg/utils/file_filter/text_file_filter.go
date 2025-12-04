package file_filter

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"os"
)

const (
	// _MinNullsForUTF16Heuristic is the minimum number of nulls needed to trust the pattern
	// A single stray null byte isn't a pattern.
	_MinNullsForUTF16Heuristic = 4
	// _FileHeaderSampleSize is the number of bytes read from a file in order to
	// determine if it's text or binary.
	_FileHeaderSampleSize = 512
	// _UTF16PatternThreshold is how strong the pattern must be (e.g., 0.9 = 90%)
	// 90% of nulls must be on *either* even or odd indices to be considered UTF-16.
	_UTF16PatternThreshold = 0.90
)

// BOM(Byte Order Mark) definitions.
var (
	bomUTF16LE = []byte{0xFF, 0xFE}
	bomUTF16BE = []byte{0xFE, 0xFF}
)

type TextFileFilter struct {
	logger *zerolog.Logger
}

func NewTextFileFilter(logger *zerolog.Logger) *TextFileFilter {
	return &TextFileFilter{logger: logger}
}

func (f *TextFileFilter) Filter(path string) bool {
	// Attempt to read the file header
	header, err := readFileHeader(path, _FileHeaderSampleSize)
	if err != nil {
		// Filters are enforced, we should exclude any files that we can't classify because of missing file header
		f.logger.Error().Msgf("failed to read file header stats: %v", err)
		return true
	}
	return !isTextContent(header)
}

// isTextContent determines if the data slice contains text content
// based on the null byte method. See: https://docs.google.com/document/d/1GYir_j0ITTxg_CqyAw8BeUZYCCUyNMAePbGw5nsTGYE/
func isTextContent(data []byte) bool {
	// Empty files are considered text
	if len(data) == 0 {
		return true
	}
	// Fast path for common text files (no nulls)
	if bytes.IndexByte(data, 0x00) == -1 {
		return true
	}

	// Nulls ARE present from this point on
	// Check for definitive text BOMs
	if isText, _ := checkBOM(data); isText {
		return true
	}

	// No BOM. Run the null-pattern heuristic to check for UTF-16
	// If the check fails, it's binary (sparse or random nulls)
	isText, _ := checkUTF16Heuristic(data)
	return isText
}

// Helper functions
// checkBOM looks for known Unicode Byte Order Marks that signify text.
func checkBOM(header []byte) (isText bool, reason string) {
	if bytes.HasPrefix(header, bomUTF16LE) {
		return true, "utf-16-le-bom"
	}
	if bytes.HasPrefix(header, bomUTF16BE) {
		return true, "utf-16-be-bom"
	}
	return false, ""
}

// checkUTF16Heuristic analyzes the *pattern* of null bytes to guess if it's UTF-16
// It returns (isText, reason). If isText is false, the reason explains why it's
// classified as binary (e.g., "has-null-random").
func checkUTF16Heuristic(header []byte) (isText bool, reason string) {
	var oddNulls, evenNulls, totalNulls int

	// Count nulls at even vs. odd indices
	for i, b := range header {
		if b != 0x00 {
			continue
		}

		totalNulls++
		if i%2 == 0 {
			evenNulls++
		} else {
			oddNulls++
		}
	}
	// Check if we have enough data to make a guess
	if totalNulls < _MinNullsForUTF16Heuristic {
		// Not enough nulls for a pattern. Safer to assume binary
		return false, "has-null-sparse"
	}

	// Calculate the pattern strength
	evenShare := float64(evenNulls) / float64(totalNulls)
	oddShare := float64(oddNulls) / float64(totalNulls)

	// Check if the pattern is strong enough
	if evenShare > _UTF16PatternThreshold || oddShare > _UTF16PatternThreshold {
		// >90% of nulls are on one side. This is a strong UTF-16 signal
		return true, "utf-16-heuristic"
	}
	// Default: Nulls are present but scattered randomly
	return false, "has-null-random"
}

func readFileHeader(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Get file size
	stat, statErr := f.Stat()
	if statErr != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", statErr)
	}
	size := stat.Size()

	// Determine the smaller of n or the actual file size
	bytesToRead := min(n, size)
	// Handle 0-byte files
	if bytesToRead == 0 {
		return []byte{}, nil
	}

	// Allocate the exact buffer size
	buf := make([]byte, int(bytesToRead))
	nr, err := f.Read(buf)
	// We only return an error if it's *not* io.EOF
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to read bytes: %w", err)
	}
	// Return the actual bytes read (buf[:nr])
	return buf[:nr], nil
}
