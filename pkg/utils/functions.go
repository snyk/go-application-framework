package utils

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
