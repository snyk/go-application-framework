package toon

import (
	"fmt"
	"strings"
)

// FormatTabularField quotes a tabular-array cell value (comma-delimited).
func FormatTabularField(value string) (string, error) {
	return formatString(value, formatContext{active: ',', inArray: true})
}

// FormatScalarValue quotes an object field value after "key: ".
func FormatScalarValue(value string) (string, error) {
	return formatString(value, formatContext{document: '\n'})
}

func formatString(value string, ctx formatContext) (string, error) {
	if err := validateCharacters(value); err != nil {
		return "", err
	}
	if needsQuoting(value, ctx) {
		return quoteString(value)
	}
	return value, nil
}

type formatContext struct {
	active   rune
	document rune
	inArray  bool
}

//nolint:gocyclo // mirrors toon-go format.NeedsQuoting rules
func needsQuoting(value string, ctx formatContext) bool {
	if len(value) == 0 {
		return true
	}
	if strings.TrimSpace(value) != value {
		return true
	}
	switch value {
	case "true", "false", "null":
		return true
	}
	if looksNumeric(value) || hasLeadingZeroDecimal(value) {
		return true
	}
	if strings.ContainsAny(value, ":\\\"[]{}") {
		return true
	}
	if strings.ContainsRune(value, '\n') || strings.ContainsRune(value, '\r') || strings.ContainsRune(value, '\t') {
		return true
	}
	if strings.HasPrefix(value, "-") {
		return true
	}
	if ctx.inArray && ctx.active != 0 && strings.ContainsRune(value, ctx.active) {
		return true
	}
	if !ctx.inArray && ctx.document != 0 && strings.ContainsRune(value, ctx.document) {
		return true
	}
	return false
}

func quoteString(value string) (string, error) {
	var b strings.Builder
	b.Grow(len(value) + 2)
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString("\\\\")
		case '"':
			b.WriteString("\\\"")
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 {
				return "", fmt.Errorf("toon: unsupported control character U+%04X in string", r)
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

func validateCharacters(value string) error {
	for _, r := range value {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return fmt.Errorf("toon: unsupported control character U+%04X in string", r)
		}
	}
	return nil
}

//nolint:gocyclo // mirrors toon-go format.LooksNumeric rules
func looksNumeric(value string) bool {
	if len(value) == 0 {
		return false
	}
	i := 0
	if value[0] == '-' {
		i++
		if i == len(value) {
			return false
		}
	}
	digits := 0
	for i < len(value) && isDigit(value[i]) {
		i++
		digits++
	}
	if digits == 0 {
		return false
	}
	if i < len(value) && value[i] == '.' {
		i++
		if i == len(value) || !isDigit(value[i]) {
			return false
		}
		for i < len(value) && isDigit(value[i]) {
			i++
		}
	}
	if i < len(value) && (value[i] == 'e' || value[i] == 'E') {
		i++
		if i < len(value) && (value[i] == '+' || value[i] == '-') {
			i++
		}
		if i == len(value) || !isDigit(value[i]) {
			return false
		}
		for i < len(value) && isDigit(value[i]) {
			i++
		}
	}
	return i == len(value)
}

func hasLeadingZeroDecimal(value string) bool {
	if len(value) < 2 {
		return false
	}
	if value[0] != '0' {
		return false
	}
	return value[1] >= '0' && value[1] <= '9'
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}
