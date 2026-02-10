package fileupload

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	uploadrevision2 "github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
	"github.com/snyk/go-application-framework/pkg/utils"
)

// Config contains configuration for the file upload client.
type Config struct {
	BaseURL string
	OrgID   OrgID
}

// HTTPClient provides high-level file upload functionality.
type HTTPClient struct {
	uploadRevisionSealableClient uploadrevision2.SealableClient
	cfg                          Config
	logger                       *zerolog.Logger
}

// Client defines the interface for the high level file upload client.
type Client interface {
	CreateRevisionFromChan(ctx context.Context, paths <-chan string, rootPath string) (UploadResult, error)
}

var _ Client = (*HTTPClient)(nil)

// NewClient creates a new high-level file upload client.
func NewClient(httpClient *http.Client, cfg Config, opts ...Option) Client {
	client := &HTTPClient{
		cfg: cfg,
	}

	for _, opt := range opts {
		opt(client)
	}

	if client.logger == nil {
		client.logger = utils.Ptr(zerolog.Nop())
	}

	if client.uploadRevisionSealableClient == nil {
		client.uploadRevisionSealableClient = uploadrevision2.NewClient(uploadrevision2.Config{
			BaseURL: cfg.BaseURL,
		}, uploadrevision2.WithHTTPClient(httpClient))
	}

	return client
}

func (c *HTTPClient) uploadBatch(ctx context.Context, revID RevisionID, batch *uploadBatch) error {
	defer batch.closeRemainingFiles()

	if batch.isEmpty() {
		return nil
	}

	err := c.uploadRevisionSealableClient.UploadFiles(ctx, c.cfg.OrgID, revID, batch.files)
	if err != nil {
		return fmt.Errorf("failed to upload files: %w", err)
	}

	return nil
}

// addPathsToRevision adds multiple file paths to an existing revision.
func (c *HTTPClient) addPathsToRevision(
	ctx context.Context,
	revisionID RevisionID,
	rootPath string,
	pathsChan <-chan string,
) (UploadResult, error) {
	res := UploadResult{
		RevisionID:    revisionID,
		FilteredFiles: make([]FilteredFile, 0),
	}

	fileSizeFilter := func(ff fileToFilter) *FilteredFile {
		fileSizeLimit := c.uploadRevisionSealableClient.GetLimits().FileSizeLimit
		if ff.Stat.Size() > fileSizeLimit {
			return &FilteredFile{
				Path:   ff.Path,
				Reason: uploadrevision2.NewFileSizeLimitError(ff.Stat.Name(), ff.Stat.Size(), fileSizeLimit),
			}
		}

		return nil
	}

	filePathLengthFilter := func(ff fileToFilter) *FilteredFile {
		filePathLengthLimit := c.uploadRevisionSealableClient.GetLimits().FilePathLengthLimit
		if len(ff.Path) > filePathLengthLimit {
			return &FilteredFile{
				Path:   ff.Path,
				Reason: uploadrevision2.NewFilePathLengthLimitError(ff.Path, len(ff.Path), filePathLengthLimit),
			}
		}

		return nil
	}

	filters := []filter{
		fileSizeFilter,
		filePathLengthFilter,
	}

	for batchResult, err := range batchPaths(rootPath, pathsChan, c.uploadRevisionSealableClient.GetLimits(), filters...) {
		if err != nil {
			// make sure to close all previously open files if an error occurs
			if batchResult != nil && batchResult.batch != nil {
				batchResult.batch.closeRemainingFiles()
			}
			return res, fmt.Errorf("failed to batch files: %w", err)
		}

		res.FilteredFiles = append(res.FilteredFiles, batchResult.filteredFiles...)

		err = c.uploadBatch(ctx, revisionID, batchResult.batch)
		if err != nil {
			return res, err
		}

		res.UploadedFilesCount += len(batchResult.batch.files)
	}

	return res, nil
}

// createRevision creates a new revision and returns its ID.
func (c *HTTPClient) createRevision(ctx context.Context) (RevisionID, error) {
	revision, err := c.uploadRevisionSealableClient.CreateRevision(ctx, c.cfg.OrgID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create revision: %w", err)
	}
	return revision.Data.ID, nil
}

// sealRevision seals a revision, making it immutable.
func (c *HTTPClient) sealRevision(ctx context.Context, revisionID RevisionID) error {
	_, err := c.uploadRevisionSealableClient.SealRevision(ctx, c.cfg.OrgID, revisionID)
	if err != nil {
		return fmt.Errorf("failed to seal revision: %w", err)
	}
	return nil
}

// CreateRevisionFromChan uploads multiple paths from a channel (files paths only, file paths are uploaded relative to rootPath), returning a revision ID.
// This is a convenience method that creates, uploads, and seals a revision.
func (c *HTTPClient) CreateRevisionFromChan(ctx context.Context, paths <-chan string, rootPath string) (UploadResult, error) {
	res := UploadResult{
		FilteredFiles: make([]FilteredFile, 0),
	}

	revisionID, err := c.createRevision(ctx)
	if err != nil {
		return UploadResult{}, err
	}
	res.RevisionID = revisionID

	res, err = c.addPathsToRevision(ctx, revisionID, rootPath, paths)
	if err != nil {
		return UploadResult{}, fmt.Errorf("failed to add paths to revision %s: %w", revisionID, err)
	}

	if res.UploadedFilesCount == 0 && len(res.FilteredFiles) == 0 {
		return res, ErrNoFilesProvided
	}

	if err := c.sealRevision(ctx, revisionID); err != nil {
		return res, err
	}

	return res, nil
}
