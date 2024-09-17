package workflow

import (
	"crypto/sha256"
	"fmt"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// DataImpl is the default implementation of the Data interface.
type DataImpl struct {
	identifier        Identifier
	header            http.Header
	payload           interface{}
	payloadLocation   Location
	logger            *zerolog.Logger
	errors            []snyk_errors.Error
	inMemoryThreshold int // in bytes
	tempDirPath       string
}

var _ Data = (*DataImpl)(nil)

type PayloadLocation int

const (
	InMemory PayloadLocation = iota
	OnDisk
)

type Location struct {
	Path   string
	Sha256 string
	Type   PayloadLocation
}

const (
	Content_type_key     string = "Content-Type"
	Content_location_key string = "Content-Location"
)

type Option = func(d *DataImpl)

func withIdentifier(id *Identifier) Option {
	return func(d *DataImpl) {
		d.identifier = *id
	}
}

func withContentType(contentType *string) Option {
	return func(d *DataImpl) {
		d.header.Add(Content_type_key, *contentType)
	}
}

func withPayload(payload *interface{}) Option {
	return func(d *DataImpl) {
		d.payload = *payload
	}
}

func WithConfiguration(config configuration.Configuration) Option {
	return func(d *DataImpl) {
		d.inMemoryThreshold = config.GetInt(configuration.IN_MEMORY_THRESHOLD_BYTES)
		d.tempDirPath = config.GetString(configuration.TEMP_DIR_PATH)
	}
}

func WithInputData(input Data) Option {
	return func(d *DataImpl) {
		if input == nil {
			// generate time based fragment
			d.identifier.Fragment = fmt.Sprintf("%d", time.Now().Nanosecond())
		} else {
			// derive fragment from input data if available
			d.identifier.Fragment = input.GetIdentifier().Fragment

			// derive content location from input
			if loc, err := input.GetMetaData(Content_location_key); err == nil {
				d.header.Add(Content_location_key, loc)
			}

			d.errors = slices.Clone(input.GetErrorList())
		}
	}
}

func WithLogger(logger *zerolog.Logger) Option {
	return func(d *DataImpl) {
		d.logger = logger
	}
}

func newDataWith(opts ...Option) Data {
	// initial DataImpl
	output := &DataImpl{
		header: http.Header{},
		payloadLocation: Location{
			Path: "",
			Type: InMemory,
		},
		logger: &zerolog.Logger{},
	}

	// configure and initialize default value for memory threshold and temp dir path.
	// Needed for cases when we call NewData() without WithConfiguration()
	// AND we do not configure IN…MEMORY_THRESHOLD_BYTES or TEMP_DIR_PATH
	c := configuration.NewInMemory()
	c.AddDefaultValue(configuration.IN_MEMORY_THRESHOLD_BYTES, configuration.StandardDefaultValueFunction(constants.SNYK_DEFAULT_IN_MEMORY_THRESHOLD_MB))
	c.AddDefaultValue(configuration.TEMP_DIR_PATH, configuration.StandardDefaultValueFunction(os.TempDir()))
	WithConfiguration(c)(output)

	for _, opt := range opts {
		opt(output)
	}

	logger := *output.logger

	// validate DataImpl
	if len(output.identifier.Path) <= 0 {
		panic("Given identifier is not a type identifier")
	}

	// update DataImpl values
	output.identifier.Scheme = "did"
	output.payloadLocation = setPayloadLocation(output.identifier, output.inMemoryThreshold, output.tempDirPath, output.payload, &logger)

	if output.payloadLocation.Type == OnDisk {
		logger.Debug().Msg("payload is on disk, nil payload in memory for cleanup")
		output.payload = nil
	}

	return output
}

// Deprecated: Use NewData with workflow.WithInputData() option instead
//
// NewDataFromInput creates a new data instance from the given input data.
//
// It will preserve the headers, metadata and errors
func NewDataFromInput(input Data, typeIdentifier Identifier, contentType string, payload interface{}, opts ...Option) Data {
	opts = append(
		[]Option{
			withIdentifier(&typeIdentifier),
			withContentType(&contentType),
			withPayload(&payload),
			WithInputData(input),
		},
		opts...)

	output := newDataWith(opts...)
	return output
}

// NewData creates a new data instance.
//
// It accepts optional parameters to configure the data instance.
//
// It will preserve the headers, metadata and errors
func NewData(id Identifier, contentType string, payload interface{}, opts ...Option) Data {
	opts = append(
		[]Option{
			withIdentifier(&id),
			withContentType(&contentType),
			withPayload(&payload),
			WithInputData(nil),
		},
		opts...)

	output := newDataWith(opts...)
	return output
}

// SetMetaData sets the headers of the given data instance.
func (d *DataImpl) SetMetaData(key string, value string) {
	d.header[key] = []string{value}
}

// GetMetaData returns the value of the given header key.
func (d *DataImpl) GetMetaData(key string) (string, error) {
	var value string
	err := fmt.Errorf("key '%s' not found", key)
	if values, ok := d.header[key]; ok {
		if len(values) > 0 {
			value = values[0]
			err = nil
		}
	}
	return value, err
}

// SetPayload sets the payload of the given data instance.
func (d *DataImpl) SetPayload(payload interface{}) {
	payloadLocation := setPayloadLocation(d.identifier, d.inMemoryThreshold, d.tempDirPath, payload, d.logger)
	if payloadLocation.Type == InMemory {
		d.payload = payload
	}
}

// GetPayload returns the payload of the given data instance.
func (d *DataImpl) GetPayload() interface{} {
	payload := d.payload
	d.logger.Trace().Msg("checking payload location")
	if d.payloadLocation.Type == OnDisk {
		d.logger.Debug().Msgf("payload location for: %s is on disk, reading from disk", d.identifier.String())
		// read file
		payloadFromFile, err := os.ReadFile(d.payloadLocation.Path)
		if err != nil {
			d.logger.Error().Msgf("error reading file: %v", err)
		} else {
			payload = payloadFromFile
			d.logger.Trace().Msg("payload read from file")
		}
	} else {
		d.logger.Debug().Msgf("payload location for: %s is in memory, returning payload", d.identifier.String())
	}
	return payload
}

// GetIdentifier returns the identifier of the given data instance.
func (d *DataImpl) GetIdentifier() Identifier {
	return d.identifier
}

// GetContentType returns the Content-Type header of the given data instance.
func (d *DataImpl) GetContentType() string {
	//nolint:errcheck // breaking api change required to fix this
	result, _ := d.GetMetaData(Content_type_key)
	return result
}

// GetContentLocation returns the Content-Location header of the given data instance.
func (d *DataImpl) GetContentLocation() string {
	//nolint:errcheck // breaking api change required to fix this
	result, _ := d.GetMetaData(Content_location_key)
	return result
}

// SetContentLocation sets the Content-Location header of the given data instance.
func (d *DataImpl) SetContentLocation(location string) {
	d.SetMetaData(Content_location_key, location)
}

// String returns a string representation of the given data instance.
func (d *DataImpl) String() string {
	return fmt.Sprintf("{DataImpl, id: \"%s\", content-type: \"%s\"}", d.identifier.String(), d.GetContentType())
}

func (d *DataImpl) GetErrorList() []snyk_errors.Error {
	return d.errors
}

func (d *DataImpl) AddError(err snyk_errors.Error) {
	d.errors = append(d.errors, err)
}

func setPayloadLocation(id Identifier, inMemoryThreshold int, tempDirPath string, payload interface{}, logger *zerolog.Logger) Location {
	payloadLocation := Location{
		Path:   "",
		Sha256: "",
		Type:   InMemory,
	}

	logger.Trace().Msg("checking if payload is []byte")
	bytes, ok := payload.([]byte)
	if !ok {
		return payloadLocation
	}
	payloadLocation.Sha256 = fmt.Sprintf("%x", sha256.Sum256(bytes))

	payloadSize := len(bytes)
	logger.Trace().Msgf("payload is []byte, comparing payload size (%d bytes) to threshold (%d bytes)", payloadSize, inMemoryThreshold)

	if payloadSize <= inMemoryThreshold || inMemoryThreshold < 0 {
		logger.Trace().Msg("payload is lower than threshold or this feature is disabled, keeping it in memory")
		return payloadLocation
	}

	logger.Trace().Msg("payload is larger than threshold, writing it to disk")
	filePath, err := writeDataToDisk(fmt.Sprintf("workflow.%s", id.Path), tempDirPath, bytes, logger)
	if err != nil {
		return payloadLocation
	}
	payloadLocation.Path = filePath
	payloadLocation.Type = OnDisk
	return payloadLocation
}

func writeDataToDisk(filename string, path string, data []byte, logger *zerolog.Logger) (filePath string, err error) {
	filepath, err := os.CreateTemp(path, fmt.Sprintf("%s.*", filename))
	if err != nil {
		logger.Error().Msgf("Error creating temp file: %v", err)
		return "", err
	}

	logger.Trace().Msgf("Setting file permissions for file: %v", filepath)
	err = filepath.Chmod(0755)
	if err != nil {
		logger.Error().Msgf("Error setting permissions on temp file: %v", err)
		return "", err
	}

	logger.Trace().Msgf("Writing payload to file: %v", filepath)
	_, err = filepath.Write(data)
	if err != nil {
		logger.Error().Msgf("Error writing to file: %v", err)
		return "", err
	}

	logger.Trace().Msgf("Payload written to file: %v", filepath)
	err = filepath.Close()
	if err != nil {
		logger.Error().Msgf("Error closing file: %v", err)
		return "", err
	}

	return filepath.Name(), nil
}
