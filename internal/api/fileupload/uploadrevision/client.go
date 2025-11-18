package uploadrevision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// SealableClient defines the interface for file upload API operations.
type SealableClient interface {
	CreateRevision(ctx context.Context, orgID OrgID) (*ResponseBody, error)
	UploadFiles(ctx context.Context, orgID OrgID, revisionID RevisionID, files []UploadFile) error
	SealRevision(ctx context.Context, orgID OrgID, revisionID RevisionID) (*SealResponseBody, error)

	GetLimits() Limits
}

// This will force go to complain if the type doesn't satisfy the interface.
var _ SealableClient = (*HTTPSealableClient)(nil)

// Config contains the configuration for the file upload client.
type Config struct {
	BaseURL string
}

// HTTPSealableClient implements the SealableClient interface for file upload operations via HTTP API.
type HTTPSealableClient struct {
	cfg        Config
	httpClient *http.Client
}

// apiVersion specifies the API version to use for requests.
const apiVersion = "2024-10-15"

const (
	fileSizeLimit         = 50_000_000  // 50MB - maximum size per individual file
	fileCountLimit        = 300_000     // 300,000 - maximum number of files per request
	totalPayloadSizeLimit = 200_000_000 // 200MB - maximum total uncompressed payload size per request
	filePathLengthLimit   = 256         // 256 - maximum length of file names
)

// NewClient creates a new file upload client with the given configuration and options.
func NewClient(cfg Config, opts ...Opt) *HTTPSealableClient {
	httpClient := &http.Client{
		Transport: http.DefaultTransport,
	}
	c := HTTPSealableClient{cfg, httpClient}

	for _, opt := range opts {
		opt(&c)
	}

	return &c
}

// CreateRevision creates a new upload revision for the specified organization.
func (c *HTTPSealableClient) CreateRevision(ctx context.Context, orgID OrgID) (*ResponseBody, error) {
	if orgID == uuid.Nil {
		return nil, ErrEmptyOrgID
	}

	body := RequestBody{
		Data: RequestData{
			Attributes: RequestAttributes{
				RevisionType: RevisionTypeSnapshot,
			},
			Type: ResourceTypeUploadRevision,
		},
	}
	buff := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buff).Encode(body); err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/upload_revisions?version=%s", c.cfg.BaseURL, orgID, apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buff)
	if err != nil {
		return nil, fmt.Errorf("failed to create revision request: %w", err)
	}
	req.Header.Set(ContentType, "application/vnd.api+json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making create revision request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return nil, handleUnexpectedStatusCodes(res.Body, res.StatusCode, res.Status, "create upload revision")
	}

	var respBody ResponseBody
	if err := json.NewDecoder(res.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode upload revision response: %w", err)
	}

	return &respBody, nil
}

// UploadFiles uploads the provided files to the specified revision. It will not close the file descriptors.
func (c *HTTPSealableClient) UploadFiles(ctx context.Context, orgID OrgID, revisionID RevisionID, files []UploadFile) error {
	if orgID == uuid.Nil {
		return ErrEmptyOrgID
	}

	if revisionID == uuid.Nil {
		return ErrEmptyRevisionID
	}

	if err := validateFiles(files); err != nil {
		return err
	}

	// Create pipe for multipart data
	pipeReader, pipeWriter := io.Pipe()
	defer pipeReader.Close()

	mpartWriter := multipart.NewWriter(pipeWriter)

	go streamFilesToPipe(pipeWriter, mpartWriter, files)
	body := compressRequestBody(pipeReader)

	// Load body bytes into memmory so go can determine the Content-Length
	// and not send the request chunked
	bts, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("failed to create upload files request: %w", err)
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/upload_revisions/%s/files?version=%s", c.cfg.BaseURL, orgID, revisionID, apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bts))
	if err != nil {
		return fmt.Errorf("failed to create upload files request: %w", err)
	}
	req.Header.Set(ContentType, mpartWriter.FormDataContentType())
	req.Header.Set(ContentEncoding, "gzip")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error making upload files request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		return handleUnexpectedStatusCodes(res.Body, res.StatusCode, res.Status, "upload files")
	}

	return nil
}

// streamFilesToPipe writes files to the multipart form.
func streamFilesToPipe(pipeWriter *io.PipeWriter, mpartWriter *multipart.Writer, files []UploadFile) {
	var streamError error
	defer func() {
		if closeErr := mpartWriter.Close(); closeErr != nil && streamError == nil {
			streamError = closeErr
		}
		pipeWriter.CloseWithError(streamError)
	}()

	for _, file := range files {
		// Create form file part
		part, err := mpartWriter.CreateFormFile(file.Path, file.Path)
		if err != nil {
			streamError = NewMultipartError(file.Path, err)
			return
		}

		if _, err := io.Copy(part, file.File); err != nil {
			streamError = fmt.Errorf("failed to copy file content for %s: %w", file.Path, err)
			return
		}
	}
}

// validateFiles validates the files before upload.
func validateFiles(files []UploadFile) error {
	if len(files) > fileCountLimit {
		return NewFileCountLimitError(len(files), fileCountLimit)
	}

	if len(files) == 0 {
		return ErrNoFilesProvided
	}

	var totalPayloadSize int64
	for _, file := range files {
		if len(file.Path) > filePathLengthLimit {
			return NewFilePathLengthLimitError(file.Path, len(file.Path), filePathLengthLimit)
		}

		fileInfo, err := file.File.Stat()
		if err != nil {
			return NewFileAccessError(file.Path, err)
		}

		if !fileInfo.Mode().IsRegular() {
			return NewSpecialFileError(file.Path, fileInfo.Mode())
		}

		if fileInfo.Size() > fileSizeLimit {
			return NewFileSizeLimitError(file.Path, fileInfo.Size(), fileSizeLimit)
		}

		totalPayloadSize += fileInfo.Size()
	}

	if totalPayloadSize > totalPayloadSizeLimit {
		return NewTotalPayloadSizeLimitError(totalPayloadSize, totalPayloadSizeLimit)
	}

	return nil
}

// SealRevision seals the specified upload revision, marking it as complete.
func (c *HTTPSealableClient) SealRevision(ctx context.Context, orgID OrgID, revisionID RevisionID) (*SealResponseBody, error) {
	if orgID == uuid.Nil {
		return nil, ErrEmptyOrgID
	}

	if revisionID == uuid.Nil {
		return nil, ErrEmptyRevisionID
	}

	body := SealRequestBody{
		Data: SealRequestData{
			ID: revisionID,
			Attributes: SealRequestAttributes{
				Sealed: true,
			},
			Type: ResourceTypeUploadRevision,
		},
	}
	buff := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buff).Encode(body); err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	url := fmt.Sprintf("%s/hidden/orgs/%s/upload_revisions/%s?version=%s", c.cfg.BaseURL, orgID, revisionID, apiVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, buff)
	if err != nil {
		return nil, fmt.Errorf("failed to create seal request: %w", err)
	}
	req.Header.Set(ContentType, "application/vnd.api+json")

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making seal revision request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, handleUnexpectedStatusCodes(res.Body, res.StatusCode, res.Status, "seal upload revision")
	}

	var respBody SealResponseBody
	if err := json.NewDecoder(res.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode upload revision response: %w", err)
	}

	return &respBody, nil
}

func handleUnexpectedStatusCodes(body io.ReadCloser, statusCode int, status, operation string) error {
	bts, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if len(bts) > 0 {
		snykErrorList, parseErr := snyk_errors.FromJSONAPIErrorBytes(bts)
		if parseErr == nil && len(snykErrorList) > 0 && snykErrorList[0].Title != "" {
			errsToJoin := []error{}
			for i := range snykErrorList {
				errsToJoin = append(errsToJoin, snykErrorList[i])
			}
			return fmt.Errorf("api error during %s: %w", operation, errors.Join(errsToJoin...))
		}
	}

	return NewHTTPError(statusCode, status, operation, bts)
}

// GetLimits returns the upload Limits defined in the low level client.
func (c *HTTPSealableClient) GetLimits() Limits {
	return Limits{
		FileCountLimit:        fileCountLimit,
		FileSizeLimit:         fileSizeLimit,
		TotalPayloadSizeLimit: totalPayloadSizeLimit,
		FilePathLengthLimit:   filePathLengthLimit,
	}
}
