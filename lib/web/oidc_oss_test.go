/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
)

func TestOSSOIDCConsoleLoginRoute(t *testing.T) {
	ctx := context.Background()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/.well-known/openid-configuration", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": idpURL(r), "authorization_endpoint": idpURL(r) + "/authorize",
			"token_endpoint": idpURL(r) + "/token", "jwks_uri": idpURL(r) + "/jwks",
		})
	}))
	defer idp.Close()

	env := newWebPack(t, 1)
	connector, err := types.NewOIDCConnector("test-oidc", types.OIDCConnectorSpecV3{
		IssuerURL: idp.URL, ClientID: "test-client", ClientSecret: "test-secret",
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		Scope:        []string{"email"},
	})
	require.NoError(t, err)
	_, err = env.server.Auth().UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)
	role, err := types.NewRole("access", types.RoleSpecV6{})
	require.NoError(t, err)
	_, err = env.server.Auth().CreateRole(ctx, role)
	require.NoError(t, err)

	clt := env.proxies[0].newClient(t)
	response, err := clt.PostJSON(ctx, clt.Endpoint("webapi", "oidc", "login", "console"), client.SSOLoginConsoleReq{
		RedirectURL: "http://localhost:12345/callback", ConnectorID: "test-oidc",
	})
	require.NoError(t, err)
	var loginResponse client.SSOLoginConsoleResponse
	require.NoError(t, json.Unmarshal(response.Bytes(), &loginResponse))
	redirect, err := url.Parse(loginResponse.RedirectURL)
	require.NoError(t, err)
	require.Equal(t, idp.URL+"/authorize", redirect.Scheme+"://"+redirect.Host+redirect.Path)
	require.NotEmpty(t, redirect.Query().Get("state"))
	require.NotEmpty(t, redirect.Query().Get("nonce"))
	require.NotEmpty(t, redirect.Query().Get("code_challenge"))
}

func idpURL(r *http.Request) string {
	return "http://" + r.Host
}
