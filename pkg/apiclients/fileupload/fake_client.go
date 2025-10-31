package fileupload

import (
	"context"
	"fmt"
	"os"

	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload/uploadrevision"
)

type FakeClient struct {
	revisions    map[RevisionID][]string
	err          error
	uploadCount  int // Tracks how many uploads have occurred
	lastRevision RevisionID
}

var _ Client = (*FakeClient)(nil)

// NewFakeClient creates a new fake client.
func NewFakeClient() *FakeClient {
	return &FakeClient{
		revisions: make(map[RevisionID][]string),
	}
}

// WithError configures the fake to return an error.
func (f *FakeClient) WithError(err error) *FakeClient {
	f.err = err
	return f
}

func (f *FakeClient) CreateRevisionFromDir(ctx context.Context, dirPath string, opts UploadOptions) (UploadResult, error) {
	if f.err != nil {
		return UploadResult{}, f.err
	}

	info, err := os.Stat(dirPath)
	if err != nil {
		return UploadResult{}, uploadrevision.NewFileAccessError(dirPath, err)
	}

	if !info.IsDir() {
		return UploadResult{}, fmt.Errorf("the provided path is not a directory: %s", dirPath)
	}

	return f.CreateRevisionFromPaths(ctx, []string{dirPath}, opts)
}

func (f *FakeClient) CreateRevisionFromFile(ctx context.Context, filePath string, opts UploadOptions) (UploadResult, error) {
	if f.err != nil {
		return UploadResult{}, f.err
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return UploadResult{}, uploadrevision.NewFileAccessError(filePath, err)
	}

	if !info.Mode().IsRegular() {
		return UploadResult{}, fmt.Errorf("the provided path is not a regular file: %s", filePath)
	}

	return f.CreateRevisionFromPaths(ctx, []string{filePath}, opts)
}

func (f *FakeClient) CreateRevisionFromPaths(ctx context.Context, paths []string, opts UploadOptions) (UploadResult, error) {
	if f.err != nil {
		return UploadResult{}, f.err
	}

	revID := uuid.New()
	f.revisions[revID] = append([]string(nil), paths...)
	f.uploadCount++
	f.lastRevision = revID

	return UploadResult{RevisionID: revID, UploadedFilesCount: len(paths)}, nil
}

func (f *FakeClient) GetRevisionPaths(revID RevisionID) []string {
	return f.revisions[revID]
}

// UploadOccurred returns true if at least one upload has been performed.
func (f *FakeClient) UploadOccurred() bool {
	return f.uploadCount > 0
}

// GetUploadCount returns the number of uploads that have occurred.
func (f *FakeClient) GetUploadCount() int {
	return f.uploadCount
}

// GetLastRevisionID returns the ID of the most recent revision created.
func (f *FakeClient) GetLastRevisionID() RevisionID {
	return f.lastRevision
}
