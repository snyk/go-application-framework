package contributor_capture

import (
	"encoding/json"
)

// The helpers here walk a JSON stream token by token, so a field an extractor
// does not want is skipped rather than read into memory.

// eachKey calls fn for each key of the object the decoder is positioned at.
// fn must consume or skip the value of the key it is handed, and returns
// stop=true to finish, leaving the rest of the object unread.
func eachKey(dec *json.Decoder, fn func(key string) (stop bool, err error)) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}

	for {
		key, ok, err := nextKey(dec)
		if err != nil || !ok {
			return err
		}

		stop, err := fn(key)
		if err != nil {
			return err
		}
		if stop {
			return nil
		}
	}
}

// walkTo positions the decoder at the value found by descending path and calls
// fn to consume it. An absent path is not an error; fn is simply not called.
func walkTo(dec *json.Decoder, path []string, fn func() error) error {
	if len(path) == 0 {
		return fn()
	}

	return eachKey(dec, func(key string) (bool, error) {
		if key != path[0] {
			return false, skipValue(dec)
		}
		return true, walkTo(dec, path[1:], fn)
	})
}

// findStringField returns the string value found by descending path, or empty
// if the path is absent. A path that does not end at a string is a shape the
// extractor does not expect, and is reported as such.
func findStringField(dec *json.Decoder, path ...string) (string, error) {
	var value string

	err := walkTo(dec, path, func() error {
		found, isString, err := nextStringValue(dec)
		if err != nil {
			return err
		}
		if !isString {
			return errUnexpectedToken
		}
		value = found
		return nil
	})

	return value, err
}

// nextKey returns the next key of an object, or ok=false at its end.
func nextKey(dec *json.Decoder) (key string, ok bool, err error) {
	token, err := dec.Token()
	if err != nil {
		return "", false, err
	}

	if delim, isDelim := token.(json.Delim); isDelim {
		if delim == '}' {
			return "", false, nil
		}
		return "", false, errUnexpectedToken
	}

	key, isKey := token.(string)
	if !isKey {
		return "", false, errUnexpectedToken
	}
	return key, true, nil
}

// nextStringValue reads the next value, reporting whether it was a string.
// A value of any other type is skipped over.
func nextStringValue(dec *json.Decoder) (value string, isString bool, err error) {
	token, err := dec.Token()
	if err != nil {
		return "", false, err
	}

	if delim, isDelim := token.(json.Delim); isDelim {
		return "", false, skipContainer(dec, delim)
	}

	value, isString = token.(string)
	return value, isString, nil
}

// skipValue consumes the next value, whatever its type.
func skipValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}

	if delim, isDelim := token.(json.Delim); isDelim {
		return skipContainer(dec, delim)
	}
	return nil
}

// skipContainer consumes the rest of an object or array whose opening
// delimiter has already been read.
func skipContainer(dec *json.Decoder, open json.Delim) error {
	if open != '{' && open != '[' {
		return errUnexpectedToken
	}

	for depth := 1; depth > 0; {
		token, err := dec.Token()
		if err != nil {
			return err
		}

		if delim, isDelim := token.(json.Delim); isDelim {
			if delim == '{' || delim == '[' {
				depth++
			} else {
				depth--
			}
		}
	}

	return nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}

	if delim, isDelim := token.(json.Delim); !isDelim || delim != want {
		return errUnexpectedToken
	}
	return nil
}
