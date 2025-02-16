// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package bundle

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFlattenStream(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		input func(t *testing.T) []byte
	}{
		{"simple", func(t *testing.T) []byte { t.Helper(); return []byte("{\n  \"name\": \"john doe\"\n}") }},
		{
			"two-deep", func(t *testing.T) []byte {
				t.Helper()
				return []byte(`{
		"this": {
			"can": {
				"host": 1,
				"child": "level",
				"?": true
			}
		}
}`)
			},
		},
		{"bundle", func(t *testing.T) []byte {
			t.Helper()
			data, err := os.ReadFile("testdata/test.bundle")
			require.NoError(t, err)
			return data
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tool := Tool{}

			res, err := tool.FlattenJSON(tc.input(t))
			require.NoError(t, err)

			var want, got any

			require.NoError(t, json.Unmarshal(tc.input(t), &want))
			require.NoError(t, json.Unmarshal(res, &got))

			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %q but expected %q", got, want)
			}
		})
	}
}
