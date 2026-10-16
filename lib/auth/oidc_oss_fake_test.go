/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	libdefaults "github.com/gravitational/teleport/lib/defaults"
)

type fakeOIDCProvider struct {
	server    *httptest.Server
	key       *rsa.PrivateKey
	badSigner *rsa.PrivateKey
	claims    map[string]interface{}
	challenge string
	nonce     string
	issuer    string
}

func newFakeOIDCProvider(t *testing.T) *fakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	fake := &fakeOIDCProvider{key: key}
	fake.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer": fake.server.URL, "authorization_endpoint": fake.server.URL + "/authorize",
				"token_endpoint": fake.server.URL + "/token", "jwks_uri": fake.server.URL + "/jwks",
			})
		case "/jwks":
			publicKey := &fake.key.PublicKey
			e := big.NewInt(int64(publicKey.E)).Bytes()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{
				map[string]interface{}{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "fake-key", "n": base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)},
			}})
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if r.Form.Get("code_verifier") == "" || oidcChallenge(r.Form.Get("code_verifier")) != fake.challenge {
				http.Error(w, "invalid PKCE verifier", http.StatusBadRequest)
				return
			}
			claims := make(map[string]interface{}, len(fake.claims)+6)
			for key, value := range fake.claims {
				claims[key] = value
			}
			if _, ok := claims["iss"]; !ok {
				claims["iss"] = fake.server.URL
			}
			if _, ok := claims["aud"]; !ok {
				claims["aud"] = "teleport-client"
			}
			if _, ok := claims["sub"]; !ok {
				claims["sub"] = "subject-1"
			}
			if _, ok := claims["iat"]; !ok {
				claims["iat"] = time.Now().Unix()
			}
			if _, ok := claims["exp"]; !ok {
				claims["exp"] = time.Now().Add(time.Minute).Unix()
			}
			if _, ok := claims["nonce"]; !ok {
				claims["nonce"] = fake.nonce
			}
			idToken, err := fake.sign(claims)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "access-token", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
		default:
			http.NotFound(w, r)
		}
	}))
	fake.issuer = fake.server.URL
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *fakeOIDCProvider) sign(claims map[string]interface{}) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "fake-key", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signer := f.key
	if f.badSigner != nil {
		signer = f.badSigner
	}
	signature, err := rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type oidcTestRig struct {
	auth *githubContext
	idp  *fakeOIDCProvider
	conn types.OIDCConnector
}

func newOIDCTestRig(t *testing.T, usernameClaim string) *oidcTestRig {
	t.Helper()
	ctx := context.Background()
	fixture := setupGithubContext(ctx, t)
	role, err := types.NewRoleV6("access", types.RoleSpecV6{Options: types.RoleOptions{MaxSessionTTL: types.Duration(time.Hour)}})
	require.NoError(t, err)
	_, err = fixture.a.CreateRole(ctx, role)
	require.NoError(t, err)
	idp := newFakeOIDCProvider(t)
	spec := types.OIDCConnectorSpecV3{
		IssuerURL: idp.issuer, ClientID: "teleport-client", ClientSecret: "test-secret",
		RedirectURLs: []string{"https://proxy.example.com/v1/webapi/oidc/callback"},
		Scope:        []string{"email", "profile", "teleport"}, UsernameClaim: usernameClaim,
		ClaimsToRoles: []types.ClaimMapping{{Claim: "teleport_roles", Value: "^(.+)$", Roles: []string{"$1"}}},
	}
	connector, err := types.NewOIDCConnector("test-oidc", spec)
	require.NoError(t, err)
	_, err = fixture.a.UpsertOIDCConnector(ctx, connector)
	require.NoError(t, err)
	idp.claims = map[string]interface{}{
		"email": "alice@example.com", "email_verified": true,
		"preferred_username": "alice", "teleport_roles": []string{"access"},
	}
	return &oidcTestRig{auth: fixture, idp: idp, conn: connector}
}

func (r *oidcTestRig) createRequest(t *testing.T, web bool) *types.OIDCAuthRequest {
	t.Helper()
	req := types.OIDCAuthRequest{ConnectorID: r.conn.GetName(), CreateWebSession: web}
	if !web {
		req.ClientRedirectURL = "http://localhost:12345/callback"
	}
	result, err := r.auth.a.CreateOIDCAuthRequest(context.Background(), req)
	require.NoError(t, err)
	parsed, err := url.Parse(result.RedirectURL)
	require.NoError(t, err)
	r.idp.challenge = parsed.Query().Get("code_challenge")
	r.idp.nonce = parsed.Query().Get("nonce")
	return result
}

func (r *oidcTestRig) callback(t *testing.T, req *types.OIDCAuthRequest) (*authclient.OIDCAuthResponse, error) {
	t.Helper()
	return r.auth.a.ValidateOIDCAuthCallback(context.Background(), url.Values{"state": {req.StateToken}, "code": {"test-code"}})
}

func TestOSSOIDCWebLoginSuccess(t *testing.T) {
	rig := newOIDCTestRig(t, "")
	req := rig.createRequest(t, true)
	response, err := rig.callback(t, req)
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", response.Username)
	require.NotNil(t, response.Session)
	user, err := rig.auth.a.GetUser(context.Background(), response.Username, false)
	require.NoError(t, err)
	require.Equal(t, []string{"access"}, user.GetRoles())
}

func TestOSSOIDCCommandLineLoginReturnsCertificates(t *testing.T) {
	rig := newOIDCTestRig(t, "")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sshKey, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	req := types.OIDCAuthRequest{ConnectorID: rig.conn.GetName(), ClientRedirectURL: "http://localhost:12345/callback", CertTTL: 10 * time.Minute, SshPublicKey: ssh.MarshalAuthorizedKey(sshKey), TlsPublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}
	created, err := rig.auth.a.CreateOIDCAuthRequest(context.Background(), req)
	require.NoError(t, err)
	parsed, err := url.Parse(created.RedirectURL)
	require.NoError(t, err)
	rig.idp.challenge = parsed.Query().Get("code_challenge")
	rig.idp.nonce = parsed.Query().Get("nonce")
	response, err := rig.callback(t, created)
	require.NoError(t, err)
	require.NotEmpty(t, response.Cert)
	require.NotEmpty(t, response.TLSCert)
}

func TestOSSOIDCTokenValidationFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*oidcTestRig)
	}{
		{name: "bad signature", mutate: func(r *oidcTestRig) { r.idp.badSigner, _ = rsa.GenerateKey(rand.Reader, 2048) }},
		{name: "wrong audience", mutate: func(r *oidcTestRig) { r.idp.claims["aud"] = "another-client" }},
		{name: "wrong nonce", mutate: func(r *oidcTestRig) { r.idp.claims["nonce"] = "incorrect" }},
		{name: "expired token", mutate: func(r *oidcTestRig) { r.idp.claims["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{name: "unverified email", mutate: func(r *oidcTestRig) { r.idp.claims["email_verified"] = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rig := newOIDCTestRig(t, "")
			test.mutate(rig)
			req := rig.createRequest(t, true)
			_, err := rig.callback(t, req)
			require.Error(t, err)
		})
	}
}

func TestOSSOIDCUnknownExpiredAndReusedState(t *testing.T) {
	t.Run("unknown state", func(t *testing.T) {
		rig := newOIDCTestRig(t, "")
		_, err := rig.auth.a.ValidateOIDCAuthCallback(context.Background(), url.Values{"state": {"unknown"}, "code": {"code"}})
		require.Error(t, err)
	})
	t.Run("expired state", func(t *testing.T) {
		rig := newOIDCTestRig(t, "")
		req := rig.createRequest(t, true)
		rig.auth.c.Advance(libdefaults.OIDCAuthRequestTTL + time.Second)
		_, err := rig.callback(t, req)
		require.Error(t, err)
	})
	t.Run("reused state", func(t *testing.T) {
		rig := newOIDCTestRig(t, "")
		req := rig.createRequest(t, true)
		_, err := rig.callback(t, req)
		require.NoError(t, err)
		_, err = rig.callback(t, req)
		require.Error(t, err)
	})
}

func TestOSSOIDCClaimsMappingAndUsernameClaim(t *testing.T) {
	rig := newOIDCTestRig(t, "preferred_username")
	req := rig.createRequest(t, true)
	response, err := rig.callback(t, req)
	require.NoError(t, err)
	require.Equal(t, "alice", response.Username)
	user, err := rig.auth.a.GetUser(context.Background(), "alice", false)
	require.NoError(t, err)
	require.Equal(t, []string{"access"}, user.GetRoles())
}

func TestOSSOIDCLocalUserNameConflict(t *testing.T) {
	rig := newOIDCTestRig(t, "")
	local, err := types.NewUser("alice@example.com")
	require.NoError(t, err)
	local.SetRoles([]string{"access"})
	_, err = rig.auth.a.CreateUser(context.Background(), local)
	require.NoError(t, err)
	req := rig.createRequest(t, true)
	_, err = rig.callback(t, req)
	require.Error(t, err)
	require.True(t, trace.IsAlreadyExists(err))
}

func oidcNonce(state string) string {
	hash := sha256.Sum256([]byte(state))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func oidcChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
