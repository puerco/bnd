// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCall(t *testing.T) {
	c := New()
	res := c.Call(context.Background())
	require.NoError(t, res)

	t.Fail()
}
