package toon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var unquotedKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

type quoteContext int

const (
	quoteObjectField quoteContext = iota
	quoteTabularCell
)

// EncodeJSON renders sorted JSON as TOON per the CLI-1838 contract.
func EncodeJSON(data []byte) ([]byte, error) {
	var value any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}

	var buf bytes.Buffer
	enc := encoder{indent: "  "}
	if err := enc.encodeRoot(&buf, value); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

type encoder struct {
	indent string
}

func (e *encoder) encodeRoot(buf *bytes.Buffer, value any) error {
	obj, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("root value must be an object")
	}
	for _, key := range sortedKeys(obj) {
		if err := e.encodeObjectField(buf, key, obj[key], 0); err != nil {
			return err
		}
	}
	return nil
}

func (e *encoder) encodeObjectField(buf *bytes.Buffer, key string, value any, depth int) error {
	prefix := e.indentLevel(depth)
	switch typed := value.(type) {
	case []any:
		return e.encodeArrayField(buf, key, typed, depth)
	case map[string]any:
		if len(typed) == 0 {
			buf.WriteString(prefix)
			buf.WriteString(formatKey(key))
			buf.WriteString(":\n")
			return nil
		}
		buf.WriteString(prefix)
		buf.WriteString(formatKey(key))
		buf.WriteString(":\n")
		for _, childKey := range sortedKeys(typed) {
			if err := e.encodeObjectField(buf, childKey, typed[childKey], depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		formatted, err := formatPrimitive(typed, quoteObjectField)
		if err != nil {
			return err
		}
		buf.WriteString(prefix)
		buf.WriteString(formatKey(key))
		buf.WriteString(": ")
		buf.WriteString(formatted)
		buf.WriteByte('\n')
		return nil
	}
}

func (e *encoder) encodeArrayField(buf *bytes.Buffer, key string, items []any, depth int) error {
	prefix := e.indentLevel(depth)
	if len(items) == 0 {
		buf.WriteString(prefix)
		buf.WriteString(formatKey(key))
		buf.WriteString(": []\n")
		return nil
	}
	if schema, ok := detectTabular(items); ok {
		buf.WriteString(prefix)
		buf.WriteString(formatTabularHeader(key, len(items), schema))
		buf.WriteByte('\n')
		for _, item := range items {
			obj := item.(map[string]any)
			if err := e.encodeTabularRow(buf, obj, schema, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if allPrimitive(items) {
		values, err := formatPrimitiveList(items, quoteObjectField)
		if err != nil {
			return err
		}
		buf.WriteString(prefix)
		buf.WriteString(formatKey(key))
		buf.WriteString("[")
		buf.WriteString(strconv.Itoa(len(items)))
		buf.WriteString("]: ")
		buf.WriteString(values)
		buf.WriteByte('\n')
		return nil
	}

	buf.WriteString(prefix)
	buf.WriteString(formatKey(key))
	buf.WriteString("[")
	buf.WriteString(strconv.Itoa(len(items)))
	buf.WriteString("]:\n")
	for _, item := range items {
		if err := e.encodeListItem(buf, item, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (e *encoder) encodeListItem(buf *bytes.Buffer, value any, depth int) error {
	switch typed := value.(type) {
	case map[string]any:
		return e.encodeListItemObject(buf, typed, depth)
	case []any:
		return e.encodeListItemArray(buf, typed, depth)
	default:
		formatted, err := formatPrimitive(typed, quoteObjectField)
		if err != nil {
			return err
		}
		buf.WriteString(e.indentLevel(depth))
		buf.WriteString("- ")
		buf.WriteString(formatted)
		buf.WriteByte('\n')
		return nil
	}
}

func (e *encoder) encodeListItemArray(buf *bytes.Buffer, items []any, depth int) error {
	if len(items) == 0 {
		buf.WriteString(e.indentLevel(depth))
		buf.WriteString("- []\n")
		return nil
	}
	if allPrimitive(items) {
		values, err := formatPrimitiveList(items, quoteObjectField)
		if err != nil {
			return err
		}
		buf.WriteString(e.indentLevel(depth))
		buf.WriteString("- [")
		buf.WriteString(strconv.Itoa(len(items)))
		buf.WriteString("]: ")
		buf.WriteString(values)
		buf.WriteByte('\n')
		return nil
	}

	buf.WriteString(e.indentLevel(depth))
	buf.WriteString("- [")
	buf.WriteString(strconv.Itoa(len(items)))
	buf.WriteString("]:\n")
	for _, item := range items {
		if err := e.encodeListItem(buf, item, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (e *encoder) encodeListItemObject(buf *bytes.Buffer, obj map[string]any, depth int) error {
	keys := sortedKeys(obj)
	if len(keys) == 0 {
		buf.WriteString(e.indentLevel(depth))
		buf.WriteString("-\n")
		return nil
	}

	firstKey := keys[0]
	firstValue := obj[firstKey]
	buf.WriteString(e.indentLevel(depth))
	buf.WriteString("- ")

	if err := e.encodeFirstListItemField(buf, firstKey, firstValue, depth); err != nil {
		return err
	}

	for _, key := range keys[1:] {
		if err := e.encodeObjectField(buf, key, obj[key], depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (e *encoder) encodeFirstListItemField(buf *bytes.Buffer, key string, value any, listDepth int) error {
	switch typed := value.(type) {
	case map[string]any:
		buf.WriteString(formatKey(key))
		buf.WriteString(":\n")
		if len(typed) == 0 {
			return nil
		}
		for _, childKey := range sortedKeys(typed) {
			if err := e.encodeObjectField(buf, childKey, typed[childKey], listDepth+2); err != nil {
				return err
			}
		}
		return nil
	case []any:
		if schema, ok := detectTabular(typed); ok {
			buf.WriteString(formatTabularHeader(key, len(typed), schema))
			buf.WriteByte('\n')
			for _, item := range typed {
				obj := item.(map[string]any)
				if err := e.encodeTabularRow(buf, obj, schema, listDepth+2); err != nil {
					return err
				}
			}
			return nil
		}
		if len(typed) == 0 {
			buf.WriteString(formatKey(key))
			buf.WriteString(": []\n")
			return nil
		}
		if allPrimitive(typed) {
			values, err := formatPrimitiveList(typed, quoteObjectField)
			if err != nil {
				return err
			}
			buf.WriteString(formatKey(key))
			buf.WriteString("[")
			buf.WriteString(strconv.Itoa(len(typed)))
			buf.WriteString("]: ")
			buf.WriteString(values)
			buf.WriteByte('\n')
			return nil
		}
		buf.WriteString(formatKey(key))
		buf.WriteString("[")
		buf.WriteString(strconv.Itoa(len(typed)))
		buf.WriteString("]:\n")
		for _, item := range typed {
			if err := e.encodeListItem(buf, item, listDepth+2); err != nil {
				return err
			}
		}
		return nil
	default:
		formatted, err := formatPrimitive(typed, quoteObjectField)
		if err != nil {
			return err
		}
		buf.WriteString(formatKey(key))
		buf.WriteString(": ")
		buf.WriteString(formatted)
		buf.WriteByte('\n')
		return nil
	}
}

func (e *encoder) encodeTabularRow(buf *bytes.Buffer, obj map[string]any, schema []tabularField, depth int) error {
	cells, err := collectTabularCells(obj, schema)
	if err != nil {
		return err
	}
	formatted := make([]string, len(cells))
	for i, cell := range cells {
		formatted[i], err = formatPrimitive(cell, quoteTabularCell)
		if err != nil {
			return err
		}
	}
	buf.WriteString(e.indentLevel(depth))
	buf.WriteString(strings.Join(formatted, ","))
	buf.WriteByte('\n')
	return nil
}

func (e *encoder) indentLevel(depth int) string {
	return strings.Repeat(e.indent, depth)
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

func allPrimitive(items []any) bool {
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

func formatKey(key string) string {
	if unquotedKeyPattern.MatchString(key) {
		return key
	}
	quoted, err := quoteString(key)
	if err != nil {
		return `"` + strings.ReplaceAll(key, `"`, `\"`) + `"`
	}
	return quoted
}

func formatTabularHeader(key string, count int, schema []tabularField) string {
	var b strings.Builder
	if key != "" {
		b.WriteString(formatKey(key))
	}
	b.WriteString("[")
	b.WriteString(strconv.Itoa(count))
	b.WriteString("]{")
	b.WriteString(formatFieldList(schema))
	b.WriteString("}:")
	return b.String()
}

func formatFieldList(fields []tabularField) string {
	parts := make([]string, len(fields))
	for i, field := range fields {
		if len(field.nested) == 0 {
			parts[i] = formatKey(field.name)
			continue
		}
		parts[i] = formatKey(field.name) + "{" + formatFieldList(field.nested) + "}"
	}
	return strings.Join(parts, ",")
}

type tabularField struct {
	name   string
	nested []tabularField
}

func detectTabular(items []any) ([]tabularField, bool) {
	if len(items) == 0 {
		return nil, false
	}

	firstObj, ok := items[0].(map[string]any)
	if !ok || firstObj == nil || len(firstObj) == 0 {
		return nil, false
	}

	fieldOrder := sortedKeys(firstObj)
	columns := make(map[string][]any, len(fieldOrder))
	for index, item := range items {
		obj, ok := item.(map[string]any)
		if !ok || obj == nil || len(obj) == 0 {
			return nil, false
		}
		keys := sortedKeys(obj)
		if index == 0 {
			fieldOrder = keys
		} else if !sameKeySet(fieldOrder, keys) {
			return nil, false
		}
		for _, key := range fieldOrder {
			columns[key] = append(columns[key], obj[key])
		}
	}

	schema := make([]tabularField, len(fieldOrder))
	for i, name := range fieldOrder {
		field, ok := classifyColumn(columns[name])
		if !ok {
			return nil, false
		}
		field.name = name
		schema[i] = field
	}
	return schema, true
}

func classifyColumn(values []any) (tabularField, bool) {
	if allPrimitive(values) {
		return tabularField{}, true
	}

	var nestedOrder []string
	for index, value := range values {
		obj, ok := value.(map[string]any)
		if !ok || obj == nil || len(obj) == 0 {
			return tabularField{}, false
		}
		keys := sortedKeys(obj)
		if index == 0 {
			nestedOrder = keys
		} else if !sameKeySet(nestedOrder, keys) {
			return tabularField{}, false
		}
	}

	nestedColumns := make(map[string][]any, len(nestedOrder))
	for _, value := range values {
		obj := value.(map[string]any)
		for _, key := range nestedOrder {
			nestedColumns[key] = append(nestedColumns[key], obj[key])
		}
	}

	nested := make([]tabularField, len(nestedOrder))
	for i, name := range nestedOrder {
		field, ok := classifyColumn(nestedColumns[name])
		if !ok {
			return tabularField{}, false
		}
		field.name = name
		nested[i] = field
	}
	return tabularField{nested: nested}, true
}

func collectTabularCells(obj map[string]any, schema []tabularField) ([]any, error) {
	cells := make([]any, 0, len(schema))
	for _, field := range schema {
		value, ok := obj[field.name]
		if !ok {
			return nil, fmt.Errorf("missing tabular field %q", field.name)
		}
		if len(field.nested) == 0 {
			cells = append(cells, value)
			continue
		}
		nested, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected nested object for field %q", field.name)
		}
		nestedCells, err := collectTabularCells(nested, field.nested)
		if err != nil {
			return nil, err
		}
		cells = append(cells, nestedCells...)
	}
	return cells, nil
}

func formatPrimitiveList(items []any, ctx quoteContext) (string, error) {
	formatted := make([]string, len(items))
	for i, item := range items {
		value, err := formatPrimitive(item, ctx)
		if err != nil {
			return "", err
		}
		formatted[i] = value
	}
	return strings.Join(formatted, ","), nil
}

func formatPrimitive(value any, ctx quoteContext) (string, error) {
	switch typed := value.(type) {
	case nil:
		return "null", nil
	case bool:
		if typed {
			return "true", nil
		}
		return "false", nil
	case string:
		if ctx == quoteTabularCell {
			return FormatTabularField(typed)
		}
		return FormatScalarValue(typed)
	case json.Number:
		return typed.String(), nil
	default:
		return "", fmt.Errorf("unsupported primitive type %T", value)
	}
}
