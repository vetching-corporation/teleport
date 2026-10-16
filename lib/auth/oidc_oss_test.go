/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package auth

import (
	"context"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
)

func TestOSSOIDCAuthRequestForMFAIsNotImplemented(t *testing.T) {
	service := &ossOIDCService{}
	_, err := service.CreateOIDCAuthRequestForMFA(context.Background(), types.OIDCAuthRequest{})
	require.Error(t, err)
	require.True(t, trace.IsNotImplemented(err))
	require.ErrorContains(t, err, "OIDC MFA requests are not supported in the OSS connector")
}
