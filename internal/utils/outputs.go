package utils

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

//go:generate $GOPATH/bin/mockgen -source=outputs.go -destination ../mocks/utils.go -package mocks -self_package github.com/snyk/go-application-framework/internal/utils/

type OutputDestination interface {
	Println(a ...any) (n int, err error)
	Remove(name string) error
	WriteFile(filename string, data []byte, perm fs.FileMode) error
}
type OutputDestinationImpl struct{}

func (odi *OutputDestinationImpl) Println(a ...any) (n int, err error) {
	return fmt.Println(a...)
}

func (odi *OutputDestinationImpl) Remove(name string) error {
	if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return os.Remove(name)
}

func (odi *OutputDestinationImpl) WriteFile(filename string, data []byte, perm fs.FileMode) error {
	return os.WriteFile(filename, data, perm)
}

func NewOutputDestination() OutputDestination {
	return &OutputDestinationImpl{}
}
