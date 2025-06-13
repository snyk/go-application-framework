package utils

import (
	"fmt"
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
