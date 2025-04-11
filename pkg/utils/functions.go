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

// PtrOf creates a pointer on the heap for the value provided.
// Because in Go you can't do something like `takesPtr(&(returnsStruct()))`.
// So instead do `takesPtr(PtrOf(returnsStruct()))`.
func PtrOf[T any](value T) *T {
	pointerToValue := new(T) // Heap may be safer than `&value`
	*pointerToValue = value
	return pointerToValue
}
