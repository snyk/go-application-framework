package fileupload

import (
	"context"
	"io/fs"
	"path/filepath"
)

func listSources(ctx context.Context, root string, filesCh chan<- string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if err := ctx.Err(); err != nil {
			return err
		}

		if !d.IsDir() {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case filesCh <- path:
			}
		}

		return nil
	})
}
