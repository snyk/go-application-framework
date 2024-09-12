// Package cueutils provides a library for data transformation using the Cue language.
// Cue is a powerful and expressive data description language well-suited for defining
// complex transformations on structured data formats.
package cueutils

import (
	"bytes"
	"fmt"
	"io/fs"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/ast"
	"cuelang.org/go/cue/load"
	"cuelang.org/go/encoding/gocode/gocodec"
)

const (
	ToTestApiFromCliTestManaged = "convert/to_testapi/from_cli_test_managed.cue"
	ToTestApiFromSarif          = "convert/to_testapi/from_sarif.cue"
	ToCliFromTestApi            = "convert/to_cli/from_testapi.cue"
	pathPrefix                  = "//" // Required for cross-platform support
)

type Transformer struct {
	inst cue.Value
}

func NewTransformer(ctx *cue.Context, name string) (*Transformer, error) {
	var devnull bytes.Buffer
	overlay := map[string]load.Source{}
	err := fs.WalkDir(EmbeddedFilesystem, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		contents, err := EmbeddedFilesystem.ReadFile(path)
		if err != nil {
			return err
		}
		overlay[pathPrefix+path] = load.FromBytes(contents)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load module source: %w", err)
	}
	insts := load.Instances([]string{pathPrefix + name}, &load.Config{
		Stdin:   &devnull,
		Overlay: overlay,
	})
	if ierr := insts[0].Err; ierr != nil {
		return nil, fmt.Errorf("failed to load transform: %w %v", ierr, ierr.InputPositions())
	}

	inst := ctx.BuildInstance(insts[0])
	if err = inst.Err(); err != nil {
		return nil, fmt.Errorf("failed to instanstiate transforms: %w", err)
	}
	return &Transformer{inst: inst}, nil
}

func (t *Transformer) Apply(input ast.Expr) (*LocalFinding, error) {
	withInput := t.inst.FillPath(cue.ParsePath("input"), input)
	if err := withInput.Err(); err != nil {
		return nil, fmt.Errorf("failed to set input: %w", err)
	}
	withOutput := withInput.LookupPath(cue.ParsePath("output"))

	if err := withOutput.Err(); err != nil {
		return nil, fmt.Errorf("failed to get output: %w", err)
	}

	// Convert from Cue.Value to relevant go type
	codec := gocodec.New(t.inst.Context(), &gocodec.Config{})
	var localFinding LocalFinding

	encodeErr := codec.Encode(withOutput, &localFinding)

	if encodeErr != nil {
		return nil, fmt.Errorf("failed to convert to type: %v", encodeErr)
	}

	return &localFinding, nil
}

func (t *Transformer) ApplyValue(v cue.Value) (cue.Value, error) {
	withInput := t.inst.FillPath(cue.ParsePath("input"), v)
	if err := withInput.Err(); err != nil {
		return withInput, fmt.Errorf("failed to set input: %w", err)
	}
	withOutput := withInput.LookupPath(cue.ParsePath("output"))
	if err := withOutput.Err(); err != nil {
		return withOutput, fmt.Errorf("failed to get output: %w", err)
	}
	return withOutput, nil
}
