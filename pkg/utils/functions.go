package utils

import (
	"fmt"
	"reflect"
	"regexp"
)

// ErrorOf is used to wrap a function call and extract the error out of it
// For example, in this code function Foo returns an error,
//
//	func Bar() (string, error){
//	 // ...
//	}
//
// The Foo function can use ErrorOf to return the error from Bar:
//
//	func Foo() error{
//		return ErrorOf(Bar())
//	}
func ErrorOf(_ any, err error) error { return err }

func ValueOf[T any](value T, _ error) T { return value }

func MatchesRegex(inputString string, regex string) (bool, error) {
	if len(regex) == 0 {
		return false, fmt.Errorf("regular expression must not be empty")
	}

	r, err := regexp.Compile(regex)
	if err != nil {
		return false, err
	}

	return r.MatchString(inputString), nil
}

// IsEmpty checks if a value is nil, zero, or empty.
// It handles nil interfaces, pointers (dereferencing them), and checks for
// zero values and empty collections (slices, maps).
func IsEmpty(value interface{}) bool {
	// 1. Handle the simplest case: a nil interface value.
	if value == nil {
		return true
	}

	// 2. Use reflection to get the value.
	v := reflect.ValueOf(value)

	// 3. Dereference pointers and interfaces until we get a concrete value.
	// We check for nil pointers along the way.
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return true
		}
		v = v.Elem()
	}

	// 4. Check if the final concrete value is its type's zero value.
	// This covers booleans, numbers, strings, channels, funcs, and nil maps/slices.
	if !v.IsValid() || v.IsZero() {
		return true
	}

	// 5. For slices and maps, IsZero() is only true if they are nil.
	// We also need to check if they are non-nil but have a length of 0.
	switch v.Kind() {
	case reflect.Slice, reflect.Map:
		return v.Len() == 0
	}

	return false
}
