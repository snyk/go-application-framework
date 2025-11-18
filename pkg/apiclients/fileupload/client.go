package fileupload

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/uuid"
	"github.com/puzpuzpuz/xsync"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api/fileupload/filters"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload/uploadrevision"
	"github.com/snyk/go-application-framework/pkg/utils"
)

// Config contains configuration for the file upload client.
type Config struct {
	BaseURL string
	OrgID   OrgID
}

// HTTPClient provides high-level file upload functionality.
type HTTPClient struct {
	uploadRevisionSealableClient uploadrevision.SealableClient
	filtersClient                filters.Client
	cfg                          Config
	filters                      Filters
	logger                       *zerolog.Logger
}

// Client defines the interface for the high level file upload client.
type Client interface {
	CreateRevisionFromPaths(ctx context.Context, paths []string) (UploadResult, error)
	CreateRevisionFromDir(ctx context.Context, dirPath string) (UploadResult, error)
	CreateRevisionFromFile(ctx context.Context, filePath string) (UploadResult, error)
}

var _ Client = (*HTTPClient)(nil)

// NewClient creates a new high-level file upload client.
func NewClient(httpClient *http.Client, cfg Config, opts ...Option) *HTTPClient {
	client := &HTTPClient{
		cfg: cfg,
		filters: Filters{
			supportedExtensions:  xsync.NewMapOf[bool](),
			supportedConfigFiles: xsync.NewMapOf[bool](),
		},
	}

	for _, opt := range opts {
		opt(client)
	}

	if client.logger == nil {
		client.logger = utils.Ptr(zerolog.Nop())
	}

	if client.uploadRevisionSealableClient == nil {
		client.uploadRevisionSealableClient = uploadrevision.NewClient(uploadrevision.Config{
			BaseURL: cfg.BaseURL,
		}, uploadrevision.WithHTTPClient(httpClient))
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
	c.filters.once.Do(func() {
		filtersResp, err := c.filtersClient.GetFilters(ctx, c.cfg.OrgID)
		if err != nil {
			c.filters.initErr = err
			return
		}

		for _, ext := range filtersResp.Extensions {
			c.filters.supportedExtensions.Store(ext, true)
		}
		for _, configFile := range filtersResp.ConfigFiles {
			// .gitignore and .dcignore should not be uploaded
			// (https://github.com/snyk/code-client/blob/d6f6a2ce4c14cb4b05aa03fb9f03533d8cf6ca4a/src/files.ts#L138)
			if configFile == ".gitignore" || configFile == ".dcignore" {
				continue
			}
			c.filters.supportedConfigFiles.Store(configFile, true)
		}
	})
	return c.filters.initErr
}

// createDeeproxyFilter creates a filter function based on the current deeproxy filtering configuration.
func (c *HTTPClient) createDeeproxyFilter(ctx context.Context) (filter, error) {
	if err := c.loadFilters(ctx); err != nil {
		return nil, fmt.Errorf("failed to load deeproxy filters: %w", err)
	}

	return func(ff fileToFilter) *FilteredFile {
		fileExt := filepath.Ext(ff.Stat.Name())
		fileName := filepath.Base(ff.Stat.Name())
		_, isSupportedExtension := c.filters.supportedExtensions.Load(fileExt)
		_, isSupportedConfigFile := c.filters.supportedConfigFiles.Load(fileName)

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
				Reason: uploadrevision.NewFileSizeLimitError(ff.Stat.Name(), ff.Stat.Size(), fileSizeLimit),
			}
		}

		return nil
	}

	filePathLengthFilter := func(ff fileToFilter) *FilteredFile {
		filePathLengthLimit := c.uploadRevisionSealableClient.GetLimits().FilePathLengthLimit
		if len(ff.Path) > filePathLengthLimit {
			return &FilteredFile{
				Path:   ff.Path,
				Reason: uploadrevision.NewFilePathLengthLimitError(ff.Path, len(ff.Path), filePathLengthLimit),
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

// addFileToRevision adds a single file to an existing revision.
func (c *HTTPClient) addFileToRevision(ctx context.Context, revisionID RevisionID, filePath string, opts uploadOptions) (UploadResult, error) {
	writableChan := make(chan string, 1)
	writableChan <- filePath
	close(writableChan)

	return c.addPathsToRevision(ctx, revisionID, filepath.Dir(filePath), writableChan, opts)
}

// addDirToRevision adds a directory and all its contents to an existing revision.
func (c *HTTPClient) addDirToRevision(ctx context.Context, revisionID RevisionID, dirPath string, opts uploadOptions) (UploadResult, error) {
	//nolint:contextcheck // will be considered later
	sources, err := forPath(dirPath, c.logger, runtime.NumCPU())
	if err != nil {
		return UploadResult{}, fmt.Errorf("failed to list files in directory %s: %w", dirPath, err)
	}

	return c.addPathsToRevision(ctx, revisionID, dirPath, sources, opts)
}

// sealRevision seals a revision, making it immutable.
func (c *HTTPClient) sealRevision(ctx context.Context, revisionID RevisionID) error {
	_, err := c.uploadRevisionSealableClient.SealRevision(ctx, c.cfg.OrgID, revisionID)
	if err != nil {
		return fmt.Errorf("failed to seal revision: %w", err)
	}
	return nil
}

// CreateRevisionFromPaths uploads multiple paths (files or directories), returning a revision ID.
// This is a convenience method that creates, uploads, and seals a revision.
func (c *HTTPClient) CreateRevisionFromPaths(ctx context.Context, paths []string) (UploadResult, error) {
	opts := uploadOptions{
		SkipDeeproxyFiltering: true,
	}

	res := UploadResult{
		FilteredFiles: make([]FilteredFile, 0),
	}

	revisionID, err := c.createRevision(ctx)
	if err != nil {
		return res, err
	}
	res.RevisionID = revisionID

	for _, pth := range paths {
		info, err := os.Stat(pth)
		if err != nil {
			return UploadResult{}, uploadrevision.NewFileAccessError(pth, err)
		}

		if info.IsDir() {
			dirUploadRes, err := c.addDirToRevision(ctx, revisionID, pth, opts)
			if err != nil {
				return res, fmt.Errorf("failed to add directory %s: %w", pth, err)
			}
			res.FilteredFiles = append(res.FilteredFiles, dirUploadRes.FilteredFiles...)
			res.UploadedFilesCount += dirUploadRes.UploadedFilesCount
		} else {
			fileUploadRes, err := c.addFileToRevision(ctx, revisionID, pth, opts)
			if err != nil {
				return res, fmt.Errorf("failed to add file %s: %w", pth, err)
			}
			res.FilteredFiles = append(res.FilteredFiles, fileUploadRes.FilteredFiles...)
			res.UploadedFilesCount += fileUploadRes.UploadedFilesCount
		}
	}

	if res.UploadedFilesCount == 0 && len(res.FilteredFiles) == 0 {
		return res, ErrNoFilesProvided
	}

	if err := c.sealRevision(ctx, revisionID); err != nil {
		return res, err
	}

	return res, nil
}

// CreateRevisionFromDir uploads a directory and all its contents, returning a revision ID.
// This is a convenience method for validating the directory path and calling CreateRevisionFromPaths with a single directory path.
func (c *HTTPClient) CreateRevisionFromDir(ctx context.Context, dirPath string) (UploadResult, error) {
	info, err := os.Stat(dirPath)
	if err != nil {
		return UploadResult{}, uploadrevision.NewFileAccessError(dirPath, err)
	}

	if !info.IsDir() {
		return UploadResult{}, fmt.Errorf("the provided path is not a directory: %s", dirPath)
	}

	return c.CreateRevisionFromPaths(ctx, []string{dirPath})
}

// CreateRevisionFromFile uploads a single file, returning a revision ID.
// This is a convenience method for validating the file path and calling CreateRevisionFromPaths with a single file path.
func (c *HTTPClient) CreateRevisionFromFile(ctx context.Context, filePath string) (UploadResult, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return UploadResult{}, uploadrevision.NewFileAccessError(filePath, err)
	}

	if !info.Mode().IsRegular() {
		return UploadResult{}, fmt.Errorf("the provided path is not a regular file: %s", filePath)
	}

	return c.CreateRevisionFromPaths(ctx, []string{filePath})
}
