package utils

import (
	"fmt"
	"io/fs"
	"os"
)

//go:generate $GOPATH/bin/mockgen -source=outputs.go -destination ../mocks/utils.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/utils/

type StdOut interface {
	Println(a ...any) (n int, err error)
}
type StdOutImpl struct{}

func (soi *StdOutImpl) Println(a ...any) (n int, err error) {
	return fmt.Println(a...)
}

type FileOut interface {
	Remove(name string) error
	WriteFile(filename string, data []byte, perm fs.FileMode) error
}
type FileOutImpl struct{}

func (foi *FileOutImpl) Remove(name string) error {
	return os.Remove(name)
}

func (foi *FileOutImpl) WriteFile(filename string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(filename, data, perm)
}

type OutputDestination interface {
	StdOut() StdOut
	FileOut() FileOut
}
type OutputDestinationImpl struct{}

func (odi *OutputDestinationImpl) StdOut() StdOut {
	return &StdOutImpl{}
}

func (odi *OutputDestinationImpl) FileOut() FileOut {
	return &FileOutImpl{}
}

func NewOutputDestination() OutputDestination {
	return &OutputDestinationImpl{}
}
