package fileupload

import (
	"context"

	"github.com/google/uuid"
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

func (f *FakeClient) CreateRevisionFromChan(ctx context.Context, paths <-chan string, rootDir string) (UploadResult, error) {
	if f.err != nil {
		return UploadResult{}, f.err
	}

	files := []string{}
	for p := range paths {
		files = append(files, p)
	}

	revID := uuid.New()
	f.revisions[revID] = files
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
