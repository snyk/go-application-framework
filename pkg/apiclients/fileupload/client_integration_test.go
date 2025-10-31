//go:build integration

package fileupload_test

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload/uploadrevision"
	"github.com/snyk/go-application-framework/pkg/apiclients/util"
)

func TestUploadFileIntegration(t *testing.T) {
	setup := util.NewIntegrationTestSetup(t)
	fileUploadClient := newFileUploadClient(setup)

	files := []uploadrevision.LoadedFile{
		{Path: "src/main.go", Content: "package main"},
	}

	dir := util.CreateTmpFiles(t, files)

	res, err := fileUploadClient.CreateRevisionFromFile(t.Context(), filepath.Join(dir.Name(), files[0].Path), fileupload.UploadOptions{})
	if err != nil {
		t.Errorf("failed to create fileupload revision: %s", err.Error())
	}
	assert.NotEqual(t, uuid.Nil, res.RevisionID)
}

func TestUploadDirectoryIntegration(t *testing.T) {
	setup := util.NewIntegrationTestSetup(t)
	fileUploadClient := newFileUploadClient(setup)

	files := []uploadrevision.LoadedFile{
		{Path: "src/main.go", Content: "package main"},
		{Path: "src/utils.go", Content: "package utils"},
		{Path: "README.md", Content: "# Project"},
	}

	dir := util.CreateTmpFiles(t, files)

	res, err := fileUploadClient.CreateRevisionFromDir(t.Context(), dir.Name(), fileupload.UploadOptions{})
	if err != nil {
		t.Errorf("failed to create fileupload revision: %s", err.Error())
	}
	assert.NotEqual(t, uuid.Nil, res.RevisionID)
}

func TestUploadLargeFileIntegration(t *testing.T) {
	setup := util.NewIntegrationTestSetup(t)
	fileUploadClient := newFileUploadClient(setup)

	content := generateFileOfSizeMegabytes(t, 30)
	files := []uploadrevision.LoadedFile{
		{Path: "src/main.go", Content: content},
	}

	dir := util.CreateTmpFiles(t, files)

	res, err := fileUploadClient.CreateRevisionFromFile(t.Context(), filepath.Join(dir.Name(), files[0].Path), fileupload.UploadOptions{})
	if err != nil {
		t.Errorf("failed to create fileupload revision: %s", err.Error())
	}
	assert.NotEqual(t, uuid.Nil, res.RevisionID)
}

func newFileUploadClient(setup *util.IntegrationTestSetup) fileupload.Client {
	return fileupload.NewClient(
		setup.Client,
		fileupload.Config{
			BaseURL: setup.Config.BaseURL,
			OrgID:   setup.Config.OrgID,
		},
	)
}

func generateFileOfSizeMegabytes(t *testing.T, megabytes int) string {
	t.Helper()
	content := make([]byte, megabytes*1024*1024)
	return string(content)
}
