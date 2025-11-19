package output_workflow

import (
	"io"

	iUtils "github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// WriterEntry is an internal structure to handle all template based writers
type WriterEntry struct {
	writer          io.WriteCloser
	mimeType        string
	templates       []string
	renderEmptyData bool
	name            string
}

// FileWriter is a public structure used to configure file based rendering
type FileWriter struct {
	NameConfigKey     string   // defines the configuration key to look up the filename under
	MimeType          string   // defines the final mime type of the rendering
	TemplateFiles     []string // defines the set of template files to use for rendering
	WriteEmptyContent bool     // specifies if anything should be written at all if the input data is empty
}

type WriterMap interface {
	PopWritersByMimetype(mimeType string) []*WriterEntry
	Length() int
}

type writerMapImpl struct {
	writers map[string][]*WriterEntry
}

type MimeType2Template struct {
	mimetype  string
	templates []string
}

func (w *writerMapImpl) PopWritersByMimetype(mimeType string) []*WriterEntry {
	writers := w.writers[mimeType]
	delete(w.writers, mimeType)
	return writers
}

func (w *writerMapImpl) Length() int {
	return len(w.writers)
}

func (we *WriterEntry) GetWriter() io.WriteCloser {
	return we.writer
}

func getDefaultWriterGeneral(config configuration.Configuration, outputDestination iUtils.OutputDestination) *WriterEntry {
	writer := &WriterEntry{
		writer: &newLineCloser{
			writer: outputDestination.GetWriter(),
		},
		mimeType:        DEFAULT_MIME_TYPE,
		renderEmptyData: true,
		name:            DEFAULT_WRITER,
	}

	if config.GetBool(OUTPUT_CONFIG_KEY_SARIF) {
		writer.mimeType = SARIF_MIME_TYPE
	}

	if config.GetBool(OUTPUT_CONFIG_KEY_JSON) {
		writer.mimeType = JSON_MIME_TYPE
	}

	if config.IsSet(OUTPUT_CONFIG_TEMPLATE_FILE) {
		writer.templates = []string{config.GetString(OUTPUT_CONFIG_TEMPLATE_FILE)}
	}

	return writer
}

func GetWritersFromConfiguration(config configuration.Configuration, outputDestination iUtils.OutputDestination) WriterMap {
	// resulting map of writers and their templates
	writerMap := &writerMapImpl{
		writers: map[string][]*WriterEntry{},
	}

	// currently the only used default writer is sarif
	if tmp := getDefaultWriterGeneral(config, outputDestination); tmp != nil {
		writerMap.writers[tmp.mimeType] = []*WriterEntry{tmp}
	}

	// default file writers
	fileWriters := []FileWriter{
		{
			OUTPUT_CONFIG_KEY_SARIF_FILE,
			SARIF_MIME_TYPE,
			[]string{},
			true,
		},
		{
			OUTPUT_CONFIG_KEY_JSON_FILE,
			JSON_MIME_TYPE,
			[]string{},
			true,
		},
	}

	// use configured file writers if available
	if tmp, ok := config.Get(OUTPUT_CONFIG_KEY_FILE_WRITERS).([]FileWriter); ok {
		fileWriters = tmp
	}

	for _, fileWriter := range fileWriters {
		if config.IsSet(fileWriter.NameConfigKey) {
			mapEntry, ok := writerMap.writers[fileWriter.MimeType]
			if !ok {
				mapEntry = []*WriterEntry{}
			}

			mapEntry = append(mapEntry, &WriterEntry{
				writer:          &delayedFileOpenWriteCloser{Filename: config.GetString(fileWriter.NameConfigKey)},
				mimeType:        fileWriter.MimeType,
				templates:       fileWriter.TemplateFiles,
				renderEmptyData: fileWriter.WriteEmptyContent,
				name:            fileWriter.NameConfigKey,
			})

			writerMap.writers[fileWriter.MimeType] = mapEntry
		}
	}

	return writerMap
}

func applyTemplatesToWriters(supportedMimeTypes []MimeType2Template, writers WriterMap) map[string]*WriterEntry {
	writerMap := map[string]*WriterEntry{}
	for _, supported := range supportedMimeTypes {
		mimetypeWriter := writers.PopWritersByMimetype(supported.mimetype)
		if len(mimetypeWriter) == 0 {
			continue
		}

		// add template to writer
		for _, writer := range mimetypeWriter {
			writer.templates = supported.templates
			writerMap[writer.name] = writer
		}
	}
	return writerMap
}
