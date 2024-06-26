package workflow

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// DataImpl is the default implementation of the Data interface.
type DataImpl struct {
	identifier Identifier
	header     http.Header
	payload    interface{}
	errors     []snyk_errors.Error
}

const (
	Content_type_key     string = "Content-Type"
	Content_location_key string = "Content-Location"
)

// NewDataFromInput creates a new data instance from the given input data.
//
// It will preserve the headers, metadata and errors
func NewDataFromInput(input Data, typeIdentifier Identifier, contentType string, payload interface{}) Data {
	if len(typeIdentifier.Path) <= 0 {
		panic("Given identifier is not a type identifier")
	}

	dataIdentifier := *typeIdentifier
	dataIdentifier.Scheme = "did"

	header := http.Header{
		Content_type_key: {contentType},
	}

	var errors []snyk_errors.Error

	if input != nil {
		// derive fragment from input data if available
		dataIdentifier.Fragment = input.GetIdentifier().Fragment

		// derive content location from input
		if loc, err := input.GetMetaData(Content_location_key); err == nil {
			header.Add(Content_location_key, loc)
		}

		errors = slices.Clone(input.GetErrorList())
	} else {
		// generate time based fragment
		dataIdentifier.Fragment = fmt.Sprintf("%d", time.Now().Nanosecond())
	}

	output := &DataImpl{
		identifier: &dataIdentifier,
		header:     header,
		payload:    payload,
		errors:     errors,
	}

	return output
}

// NewData creates a new data instance.
func NewData(id Identifier, contentType string, payload interface{}) Data {
	output := NewDataFromInput(nil, id, contentType, payload)
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
	d.payload = payload
}

// GetPayload returns the payload of the given data instance.
func (d *DataImpl) GetPayload() interface{} {
	return d.payload
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
