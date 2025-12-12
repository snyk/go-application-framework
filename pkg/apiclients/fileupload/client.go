package fileupload

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"net/http"
	"os"
	"path/filepath"

	fileuploadinternal "github.com/snyk/go-application-framework/internal/api/fileupload"
	"github.com/snyk/go-application-framework/internal/api/fileupload/filters"
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
	filtersClient                filters.Client
	cfg                          Config
	filters                      fileuploadinternal.Filters
	logger                       *zerolog.Logger
}

// Client defines the interface for the high level file upload client.
type Client interface {
	CreateRevisionFromPaths(ctx context.Context, paths []string, rootPath string) (UploadResult, error)
	CreateRevisionFromChan(ctx context.Context, paths <-chan string, rootPath string) (UploadResult, error)
	CreateRevisionFromFile(ctx context.Context, filePath string, rootPath string) (UploadResult, error)
	CreateRevisionFromDir(ctx context.Context, dirPath string) (UploadResult, error)
}

var _ Client = (*HTTPClient)(nil)

// NewClient creates a new high-level file upload client.
func NewClient(httpClient *http.Client, cfg Config, opts ...Option) Client {
	client := &HTTPClient{
		cfg: cfg,
		filters: fileuploadinternal.Filters{
			SupportedExtensions:  xsync.NewMapOf[bool](),
			SupportedConfigFiles: xsync.NewMapOf[bool](),
		},
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

	if client.filtersClient == nil {
		client.filtersClient = filters.NewDeeproxyClient(filters.Config{
			BaseURL:   cfg.BaseURL,
			IsFedRamp: false, //cfg.IsFedRamp,
		}, filters.WithHTTPClient(httpClient))
	}

	return client
}

func (c *HTTPClient) loadFilters(ctx context.Context) error {
	c.filters.Once.Do(func() {
		filtersResp, err := c.filtersClient.GetFilters(ctx, c.cfg.OrgID)
		if err != nil {
			c.filters.InitErr = err
			return
		}

		for _, ext := range filtersResp.Extensions {
			c.filters.SupportedExtensions.Store(ext, true)
		}
		for _, configFile := range filtersResp.ConfigFiles {
			// .gitignore and .dcignore should not be uploaded
			// (https://github.com/snyk/code-client/blob/d6f6a2ce4c14cb4b05aa03fb9f03533d8cf6ca4a/src/files.ts#L138)
			if configFile == ".gitignore" || configFile == ".dcignore" {
				continue
			}
			c.filters.SupportedConfigFiles.Store(configFile, true)
		}
	})
	return c.filters.InitErr
}

// createDeeproxyFilter creates a filter function based on the current deeproxy filtering configuration.
func (c *HTTPClient) createDeeproxyFilter(ctx context.Context) (filter, error) {
	if err := c.loadFilters(ctx); err != nil {
		return nil, fmt.Errorf("failed to load deeproxy filters: %w", err)
	}

	return func(ff fileToFilter) *FilteredFile {
		fileExt := filepath.Ext(ff.Stat.Name())
		fileName := filepath.Base(ff.Stat.Name())
		_, isSupportedExtension := c.filters.SupportedExtensions.Load(fileExt)
		_, isSupportedConfigFile := c.filters.SupportedConfigFiles.Load(fileName)

		if !isSupportedExtension && !isSupportedConfigFile {
			var reason error
			if !isSupportedConfigFile {
				reason = errors.Join(reason, fmt.Errorf("file name is not a part of the supported config files: %s", fileName))
			}
			if !isSupportedExtension {
				reason = errors.Join(reason, fmt.Errorf("file extension is not supported: %s", fileExt))
			}
			return &FilteredFile{
				Path:   ff.Path,
				Reason: reason,
			}
		}

		return nil
	}, nil
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
	opts uploadOptions,
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
	if !opts.SkipDeeproxyFiltering {
		deeproxyFilter, err := c.createDeeproxyFilter(ctx)
		if err != nil {
			return res, err
		}

		filters = append(filters, deeproxyFilter)
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

// CreateRevisionFromPaths uploads multiple paths (files or directories, file paths are uploaded relative to rootPath), returning a revision ID.
// This is a convenience method that creates, uploads, and seals a revision.
func (c *HTTPClient) CreateRevisionFromPaths(ctx context.Context, paths []string, rootPath string) (UploadResult, error) {
	res := UploadResult{
		FilteredFiles: make([]FilteredFile, 0),
	}

	revisionID, err := c.createRevision(ctx)
	if err != nil {
		return UploadResult{}, err
	}

	res.RevisionID = revisionID

	g, gCtx := errgroup.WithContext(ctx)
	pathsChan := make(chan string)

	// setup producer -> collects files and pushes them to pathsChan
	g.Go(func() error {
		defer close(pathsChan)

		for _, pth := range paths {
			if gErr := gCtx.Err(); gErr != nil {
				return gErr
			}

			info, statErr := os.Stat(pth)
			if statErr != nil {
				c.logger.Error().Err(statErr).Str("path", pth).Msg("failed to stat path")
				return uploadrevision2.NewFileAccessError(pth, statErr)
			}

			if info.IsDir() {
				if readErr := listSources(gCtx, pth, pathsChan); readErr != nil {
					c.logger.Error().Err(readErr).Str("path", pth).Msg("failed to read directory")
					return uploadrevision2.NewFileAccessError(pth, readErr)
				}
			} else {
				select {
				case <-gCtx.Done():
					return gCtx.Err()
				default:
					pathsChan <- pth
				}
			}
		}
		return nil
	})

	// setup consumer -> reads files from pathsChan and batches them to be uploaded
	g.Go(func() error {
		opts := uploadOptions{SkipDeeproxyFiltering: true}
		res, err = c.addPathsToRevision(gCtx, revisionID, rootPath, pathsChan, opts)
		if err != nil {
			return fmt.Errorf("failed to add paths to revision %s: %w", revisionID, err)
		}
		return nil
	})

	if gErr := g.Wait(); gErr != nil {
		return UploadResult{}, gErr
	}

	if res.UploadedFilesCount == 0 && len(res.FilteredFiles) == 0 {
		return res, ErrNoFilesProvided
	}

	if err := c.sealRevision(ctx, revisionID); err != nil {
		return res, err
	}

	return res, nil
}

// CreateRevisionFromDir uploads a directory and all its contents (file paths are uploaded relative to rootPath), returning a revision ID.
// This is a convenience method for validating the directory path and calling CreateRevisionFromPaths with a single directory path.
func (c *HTTPClient) CreateRevisionFromDir(ctx context.Context, dirPath string) (UploadResult, error) {
	info, err := os.Stat(dirPath)
	if err != nil {
		return UploadResult{}, uploadrevision2.NewFileAccessError(dirPath, err)
	}

	if !info.IsDir() {
		return UploadResult{}, fmt.Errorf("the provided path is not a directory: %s", dirPath)
	}

	return c.CreateRevisionFromPaths(ctx, []string{dirPath}, dirPath)
}

// CreateRevisionFromFile uploads a single file (file path is uploaded relative to rootPath), returning a revision ID.
// This is a convenience method for validating the file path and calling CreateRevisionFromPaths with a single file path.
func (c *HTTPClient) CreateRevisionFromFile(ctx context.Context, filePath, rootPath string) (UploadResult, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return UploadResult{}, uploadrevision2.NewFileAccessError(filePath, err)
	}

	if !info.Mode().IsRegular() {
		return UploadResult{}, fmt.Errorf("the provided path is not a regular file: %s", filePath)
	}

	return c.CreateRevisionFromPaths(ctx, []string{filePath}, rootPath)
}

// CreateRevisionFromChan uploads multiple paths from a channel (files or directories, file paths are uploaded relative to rootPath), returning a revision ID.
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

	opts := uploadOptions{SkipDeeproxyFiltering: true}
	res, err = c.addPathsToRevision(ctx, revisionID, rootPath, paths, opts)
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
