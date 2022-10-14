package utils

import (
	"bufio"
	"io/fs"
	"os"
)

const (
	FILEPERM_755 fs.FileMode = 0755 // Owner=rwx, Group=r-x, Other=r-x
)

func WriteToFile(filePath string, data string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}

	defer file.Close()

	w := bufio.NewWriter(file)
	_, err = w.WriteString(data)
	if err != nil {
		return err
	}

	return w.Flush()
}
