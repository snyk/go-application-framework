package toon

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var unquotedKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// Kind distinguishes containers from scalar JSON values for templates.
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

func sortedKeys(obj map[string]any) []string {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sameKeySet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

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

func FormatKey(key string) string {
	if unquotedKeyPattern.MatchString(key) {
		return key
	}
	quoted, err := quoteString(key)
	if err != nil {
		return `"` + strings.ReplaceAll(key, `"`, `\"`) + `"`
	}
	return quoted
}

type TabularField struct {
	Name   string
	Nested []TabularField
}

func TabularFields(items []any) []TabularField {
	if len(items) == 0 {
		return nil
	}

	firstObj, ok := items[0].(map[string]any)
	if !ok || firstObj == nil || len(firstObj) == 0 {
		return nil
	}

	fieldOrder := sortedKeys(firstObj)
	columns := make(map[string][]any, len(fieldOrder))
	for index, item := range items {
		obj, ok := item.(map[string]any)
		if !ok || obj == nil || len(obj) == 0 {
			return nil
		}
		keys := sortedKeys(obj)
		if index == 0 {
			fieldOrder = keys
		} else if !sameKeySet(fieldOrder, keys) {
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

	var nestedOrder []string
	for index, value := range values {
		obj, ok := value.(map[string]any)
		if !ok || obj == nil || len(obj) == 0 {
			return TabularField{}, false
		}
		keys := sortedKeys(obj)
		if index == 0 {
			nestedOrder = keys
		} else if !sameKeySet(nestedOrder, keys) {
			return TabularField{}, false
		}
	}

	nestedColumns := make(map[string][]any, len(nestedOrder))
	for _, value := range values {
		obj, ok := value.(map[string]any)
		if !ok || obj == nil || len(obj) == 0 {
			return TabularField{}, false
		}
		for _, key := range nestedOrder {
			nestedColumns[key] = append(nestedColumns[key], obj[key])
		}
	}

	nested := make([]TabularField, len(nestedOrder))
	for i, name := range nestedOrder {
		field, ok := classifyColumn(nestedColumns[name])
		if !ok {
			return TabularField{}, false
		}
		field.Name = name
		nested[i] = field
	}
	return TabularField{Nested: nested}, true
}

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
