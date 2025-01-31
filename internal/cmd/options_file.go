// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

type outFileOptions struct {
	OutPath string
}

func (o *outFileOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&o.OutPath,
		"out",
		"o",
		"",
		"file path to write the output to (default STDOUT)",
	)
}

func (o *outFileOptions) Validate() error {
	return nil
}

func (o *outFileOptions) OutputWriter() (io.Writer, func(), error) {
	if o.OutPath == "" || o.OutPath == "-" {
		return os.Stdout, func() {}, nil
	}

	out, err := os.Create(o.OutPath)
	if err != nil {
		return nil, nil, fmt.Errorf("opening utput file: %w", err)
	}

	return out, func() { out.Close() }, nil
}

type bundleOptions struct {
	Path string
}

func (o *bundleOptions) Validate() error {
	if o.Path == "" {
		return fmt.Errorf("path to bundle file not defined")
	}
	if o.Path != "-" {
		_, err := os.Stat(o.Path)
		if err != nil {
			return fmt.Errorf("checking attestation path: %w", err)
		}
	}
	return nil
}

func (o *bundleOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&o.Path,
		"bundle",
		"b",
		"",
		"path to the bundle file",
	)
}

func (o *bundleOptions) SetBundlePath(path string) error {
	if path == "" {
		return nil
	}
	if o.Path != "" {
		return fmt.Errorf("cannot define --bundle if a bundle was supplied as positional argument")
	}
	o.Path = path
	return nil
}

func (o *bundleOptions) OpenBundle() (io.Reader, func(), error) {
	if o.Path == "" {
		return nil, nil, fmt.Errorf("bundle path nt defined")
	}

	if o.Path == "-" {
		return os.Stdin, func() {}, nil
	}

	f, err := os.Open(o.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening bundle file: %w", err)
	}

	return f, func() { f.Close() }, nil
}

func (o *bundleOptions) ReadBundle() ([]byte, error) {
	var f io.Reader
	if o.Path == "-" {
		f = os.Stdin
	} else {
		var err error
		f, err = os.Open(o.Path)
		if err != nil {
			return nil, fmt.Errorf("opening bundle file: %w", err)
		}
		defer f.(*os.File).Close()
	}

	bundle, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading bundle data: %s", err)
	}
	return bundle, nil

}
