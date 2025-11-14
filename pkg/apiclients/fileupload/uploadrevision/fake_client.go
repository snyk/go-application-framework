package uploadrevision

import (
	"context"
	"fmt"
	"io"

	"github.com/google/uuid"
)

type LoadedFile struct {
	Path    string
	Content string
}

// revisionState holds the in-memory state for a single revision.
type revisionState struct {
	orgID  OrgID
	sealed bool
	files  []LoadedFile
}

// FakeSealableClient is a mock implementation of the SealableClient for testing.
// It tracks revisions in memory and enforces the revision lifecycle (create -> upload -> seal).
type FakeSealableClient struct {
	cfg       FakeClientConfig
	revisions map[RevisionID]*revisionState
}

type FakeClientConfig struct {
	Limits
}

var _ SealableClient = (*FakeSealableClient)(nil)

// NewFakeSealableClient creates a new instance of the fake client.
func NewFakeSealableClient(cfg FakeClientConfig) *FakeSealableClient {
	return &FakeSealableClient{
		cfg:       cfg,
		revisions: make(map[RevisionID]*revisionState),
	}
}

func (f *FakeSealableClient) CreateRevision(_ context.Context, orgID OrgID) (*ResponseBody, error) {
	newRevisionID := uuid.New()
	f.revisions[newRevisionID] = &revisionState{
		orgID:  orgID,
		sealed: false,
	}

	return &ResponseBody{
		Data: ResponseData{
			ID: newRevisionID,
		},
	}, nil
}

func (f *FakeSealableClient) UploadFiles(_ context.Context, orgID OrgID, revisionID RevisionID, files []UploadFile) error {
	rev, ok := f.revisions[revisionID]
	if !ok {
		return fmt.Errorf("revision %s not found", revisionID)
	}

	if rev.orgID != orgID {
		return fmt.Errorf("orgID mismatch for revision %s", revisionID)
	}

	if rev.sealed {
		return fmt.Errorf("revision %s is sealed and cannot be modified", revisionID)
	}

	if len(files) > f.cfg.FileCountLimit {
		return NewFileCountLimitError(len(files), f.cfg.FileCountLimit)
	}

	if len(files) == 0 {
		return ErrNoFilesProvided
	}

	var totalPayloadSize int64
	for _, file := range files {
		fileInfo, err := file.File.Stat()
		if err != nil {
			return NewFileAccessError(file.Path, err)
		}

		if !fileInfo.Mode().IsRegular() {
			return NewSpecialFileError(file.Path, fileInfo.Mode())
		}

		if fileInfo.Size() > f.cfg.FileSizeLimit {
			return NewFileSizeLimitError(file.Path, fileInfo.Size(), f.cfg.FileSizeLimit)
		}

		totalPayloadSize += fileInfo.Size()
	}

	if totalPayloadSize > f.cfg.TotalPayloadSizeLimit {
		return NewTotalPayloadSizeLimitError(totalPayloadSize, f.cfg.TotalPayloadSizeLimit)
	}

	for _, file := range files {
		bts, err := io.ReadAll(file.File)
		if err != nil {
			return err
		}
		rev.files = append(rev.files, LoadedFile{
			Path:    file.Path,
			Content: string(bts),
		})
	}
	return nil
}

func (f *FakeSealableClient) SealRevision(_ context.Context, orgID OrgID, revisionID RevisionID) (*SealResponseBody, error) {
	rev, ok := f.revisions[revisionID]
	if !ok {
		return nil, fmt.Errorf("revision %s not found", revisionID)
	}

	if rev.orgID != orgID {
		return nil, fmt.Errorf("orgID mismatch for revision %s", revisionID)
	}

	rev.sealed = true
	return &SealResponseBody{}, nil
}

// GetSealedRevisionFiles is a test helper to retrieve files for a sealed revision.
// It is not part of the SealableClient interface.
func (f *FakeSealableClient) GetSealedRevisionFiles(revisionID RevisionID) ([]LoadedFile, error) {
	rev, ok := f.revisions[revisionID]
	if !ok {
		return nil, fmt.Errorf("revision %s not found", revisionID)
	}

	if !rev.sealed {
		return nil, fmt.Errorf("revision %s is not sealed", revisionID)
	}

	return rev.files, nil
}

func (f *FakeSealableClient) GetLimits() Limits {
	return f.cfg.Limits
}
