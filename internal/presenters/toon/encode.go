package toon

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
)

var unquotedKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// Kind returns object, array, or scalar for TOON templates.
func Kind(value any) string {
	switch value.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		return "scalar"
	}
}

// AllPrimitive reports whether every array item is a JSON scalar.
func AllPrimitive(items []any) bool {
	for _, item := range items {
		if !isPrimitive(item) {
			return false
		}
	}
	return true
}

func isPrimitive(value any) bool {
	switch value.(type) {
	case nil, bool, string, json.Number:
		return true
	default:
		return false
	}
}

// FormatKey returns a quoted or bare TOON object key.
func FormatKey(key string) string {
	if unquotedKeyPattern.MatchString(key) {
		return key
	}
	return quoteString(key)
}

type TabularField struct {
	Name   string
	Nested []TabularField
}

// TabularFields returns the column schema for a uniform object array, or nil.
func TabularFields(items []any) []TabularField {
	if len(items) == 0 {
		return nil
	}

	firstObj, ok := items[0].(map[string]any)
	if !ok || firstObj == nil || len(firstObj) == 0 {
		return nil
	}

	fieldOrder := slices.Sorted(maps.Keys(firstObj))
	columns := make(map[string][]any, len(fieldOrder))
	for index, item := range items {
		obj, ok := item.(map[string]any)
		if !ok || obj == nil || len(obj) == 0 {
			return nil
		}
		keys := slices.Sorted(maps.Keys(obj))
		if index == 0 {
			fieldOrder = keys
		} else if !slices.Equal(fieldOrder, keys) {
			return nil
		}
		for _, key := range fieldOrder {
			columns[key] = append(columns[key], obj[key])
		}
	}

	schema := make([]TabularField, len(fieldOrder))
	for i, name := range fieldOrder {
		field, ok := classifyColumn(columns[name])
		if !ok {
			return nil
		}
		field.Name = name
		schema[i] = field
	}
	return schema
}

func classifyColumn(values []any) (TabularField, bool) {
	if AllPrimitive(values) {
		return TabularField{}, true
	}
	nested := TabularFields(values)
	return TabularField{Nested: nested}, len(nested) > 0
}

// TabularCells returns the flattened row values for a tabular schema.
func TabularCells(obj map[string]any, schema []TabularField) ([]any, error) {
	cells := make([]any, 0, len(schema))
	for _, field := range schema {
		value, ok := obj[field.Name]
		if !ok {
			return nil, fmt.Errorf("missing tabular field %q", field.Name)
		}
		if len(field.Nested) == 0 {
			cells = append(cells, value)
			continue
		}
		nested, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected nested object for field %q", field.Name)
		}
		nestedCells, err := TabularCells(nested, field.Nested)
		if err != nil {
			return nil, err
		}
		cells = append(cells, nestedCells...)
	}
	return cells, nil
}

// FormatPrimitive renders a JSON scalar as a TOON literal.
func FormatPrimitive(value any, tabular bool) (string, error) {
	switch typed := value.(type) {
	case nil:
		return "null", nil
	case bool:
		if typed {
			return "true", nil
		}
		return "false", nil
	case string:
		if tabular {
			return FormatTabularField(typed)
		}
		return FormatScalarValue(typed)
	case json.Number:
		return typed.String(), nil
	default:
		return "", fmt.Errorf("unsupported primitive type %T", value)
	}
}
