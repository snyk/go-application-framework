package logging

//go:generate go tool github.com/golang/mock/mockgen -destination=mocks/zerolog_mock.go -package=mocks github.com/rs/zerolog LevelWriter
