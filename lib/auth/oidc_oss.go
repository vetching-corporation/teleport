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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gravitational/trace"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/types/wrappers"
	"github.com/gravitational/teleport/api/utils/keys/hardwarekey"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/client/sso"
	libdefaults "github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

type ossOIDCService struct {
	auth *Server
}

func (s *ossOIDCService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	connector, err := s.getConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if !req.CreateWebSession {
		ceremony := sso.CeremonyTypeLogin
		if req.SSOTestFlow {
			ceremony = sso.CeremonyTypeTest
		}
		if err := sso.ValidateClientRedirect(req.ClientRedirectURL, ceremony, connector.GetClientRedirectSettings()); err != nil {
			return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
		}
	}
	state, err := utils.CryptoRandomHex(libdefaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	nonce := oidcNonceFromState(state)
	verifier := req.PkceVerifier
	if verifier == "" {
		verifier = oauth2.GenerateVerifier()
	}
	ctx, _, err = oidcHTTPContext(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	provider, err := oidc.NewProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return nil, trace.Wrap(err, "failed to discover OIDC provider")
	}
	redirectURL := connector.GetRedirectURLs()[0]
	config := oauth2.Config{
		ClientID:     connector.GetClientID(),
		ClientSecret: connector.GetClientSecret(),
		Endpoint:     oidcOAuthEndpoint(provider.Endpoint()),
		RedirectURL:  redirectURL,
		Scopes:       append([]string{oidc.ScopeOpenID}, connector.GetScope()...),
	}
	params := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", nonce)}
	params = append(params, oauth2.S256ChallengeOption(verifier))
	if prompt := connector.GetPrompt(); prompt != "" {
		params = append(params, oauth2.SetAuthURLParam("prompt", prompt))
	}
	if acr := connector.GetACR(); acr != "" {
		params = append(params, oauth2.SetAuthURLParam("acr_values", acr))
	}
	if maxAge, ok := connector.GetMaxAge(); ok {
		params = append(params, oauth2.SetAuthURLParam("max_age", strconv.FormatInt(int64(maxAge.Seconds()), 10)))
	}
	if req.LoginHint != "" {
		params = append(params, oauth2.SetAuthURLParam("login_hint", req.LoginHint))
	}
	req.StateToken = state
	req.PkceVerifier = verifier
	req.RedirectURL = config.AuthCodeURL(state, params...)
	if err := s.auth.Services.CreateOIDCAuthRequest(ctx, req, libdefaults.OIDCAuthRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

func (s *ossOIDCService) CreateOIDCAuthRequestForMFA(context.Context, types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	return nil, trace.NotImplemented("OIDC MFA requests are not supported in the OSS connector")
}

func (s *ossOIDCService) getConnector(ctx context.Context, req types.OIDCAuthRequest) (types.OIDCConnector, error) {
	if req.SSOTestFlow {
		if req.ConnectorSpec == nil || req.ConnectorID == "" {
			return nil, trace.BadParameter("connector spec and ID are required for OIDC test flow")
		}
		return types.NewOIDCConnector(req.ConnectorID, *req.ConnectorSpec)
	}
	connector, err := s.auth.GetOIDCConnector(ctx, req.ConnectorID, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}

func (s *ossOIDCService) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	diag := NewSSODiagContext(types.KindOIDC, s.auth)
	diagService := s.auth.Services.IdentityInternal
	if errParam := q.Get("error"); errParam != "" {
		err := trace.WithUserMessage(trace.OAuth2("invalid_request", errParam, q), "OIDC provider returned error: %v [%v]", q.Get("error_description"), errParam)
		return s.finishOIDCLogin(ctx, diag, diagService, nil, err)
	}
	state := q.Get("state")
	if state == "" {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.BadParameter("missing state query param"))
	}
	diag.RequestID = state
	code := q.Get("code")
	if code == "" {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.BadParameter("missing code query param"))
	}
	req, err := s.auth.Services.GetOIDCAuthRequest(ctx, state)
	if err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err, "failed to get OIDC auth request"))
	}
	diag.Info.TestFlow = req.SSOTestFlow
	if err := s.consumeRequest(ctx, state); err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err, "OIDC auth request was already used"))
	}
	connector, err := s.getConnector(ctx, *req)
	if err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
	}
	ctx, httpClient, err := oidcHTTPContext(ctx)
	if err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
	}
	provider, err := oidc.NewProvider(ctx, connector.GetIssuerURL())
	if err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err, "failed to discover OIDC provider"))
	}
	config := oauth2.Config{
		ClientID: connector.GetClientID(), ClientSecret: connector.GetClientSecret(),
		Endpoint: oidcOAuthEndpoint(provider.Endpoint()), RedirectURL: connector.GetRedirectURLs()[0],
	}
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(req.PkceVerifier))
	if err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err, "failed to exchange OIDC authorization code"))
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.BadParameter("OIDC token response did not contain an ID token"))
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: connector.GetClientID(), Now: s.auth.GetClock().Now})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err, "failed to verify OIDC ID token"))
	}
	claims := make(map[string]interface{})
	if err := idToken.Claims(&claims); err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
	}
	now := s.auth.GetClock().Now()
	if idToken.Expiry.Before(now.Add(-time.Minute)) {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.AccessDenied("OIDC ID token has expired"))
	}
	if idToken.Nonce != oidcNonceFromState(state) {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.AccessDenied("OIDC ID token nonce does not match"))
	}
	if issuedAt, ok := claims["iat"].(float64); !ok || time.Unix(int64(issuedAt), 0).After(s.auth.GetClock().Now().Add(time.Minute)) {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.AccessDenied("OIDC ID token has an invalid issued-at time"))
	}
	if !connector.GetAllowUnverifiedEmail() && claims["email_verified"] != true {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.AccessDenied("OIDC email address is not verified"))
	}
	var discovery struct {
		UserinfoEndpoint string `json:"userinfo_endpoint"`
	}
	if err := provider.Claims(&discovery); err == nil && discovery.UserinfoEndpoint != "" {
		userInfo, err := fetchOIDCUserInfo(ctx, httpClient, discovery.UserinfoEndpoint, token)
		if err != nil {
			return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err, "failed to retrieve OIDC userinfo"))
		}
		if subject, ok := userInfo["sub"].(string); !ok || subject != idToken.Subject {
			return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.AccessDenied("OIDC userinfo subject does not match ID token subject"))
		}
		for key, value := range userInfo {
			if _, exists := claims[key]; !exists {
				claims[key] = value
			}
		}
	}
	diag.Info.OIDCClaims = types.OIDCClaims(claims)
	diag.Info.OIDCClaimsToRoles = connector.GetClaimsToRoles()
	diag.Info.OIDCIdentity = &types.OIDCIdentity{ID: idToken.Subject, Email: oidcClaimString(claims["email"]), ExpiresAt: idToken.Expiry}
	usernameClaim := connector.GetUsernameClaim()
	if usernameClaim == "" {
		usernameClaim = "email"
	}
	username := oidcClaimString(claims[usernameClaim])
	if username == "" || idToken.Subject == "" {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.BadParameter("OIDC identity is missing username or subject"))
	}
	traits := map[string][]string{}
	for key, value := range claims {
		traits[key] = oidcClaimValues(value)
	}
	traits[constants.TraitLogins] = []string{username}
	diag.Info.OIDCTraitsFromClaims = wrappers.Traits(traits)
	diag.Info.OIDCConnectorTraitMapping = connector.GetTraitMappings()
	evaluation, err := s.auth.GetLoginRuleEvaluator().Evaluate(ctx, &loginrule.EvaluationInput{Traits: traits})
	if err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
	}
	traits = evaluation.Traits
	diag.Info.AppliedLoginRules = evaluation.AppliedRules
	warnings, roles := services.TraitsToRoles(connector.GetTraitMappings(), traits)
	diag.Info.OIDCClaimsToRolesWarnings = &types.SSOWarnings{Warnings: warnings}
	if len(roles) == 0 {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.AccessDenied("OIDC claims did not map to any Teleport roles"))
	}
	rolesWithContext, err := services.FetchRolesWithContext(roles, s.auth, services.RoleTemplateContext{Username: username, Traits: traits})
	if err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
	}
	ttl := rolesWithContext.AdjustSessionTTL(apidefaults.MaxCertDuration)
	ttl = utils.MinTTL(ttl, req.CertTTL)
	diag.Info.CreateUserParams = &types.CreateUserParams{ConnectorName: connector.GetName(), Username: username, Roles: roles, Traits: traits, SessionTTL: types.Duration(ttl)}
	// Unlike the GitHub connector, OIDC users do not expire with the session: the identity provider manages their lifecycle and deletes or locks them on offboarding, and an expiring record would read as an unlinked account between logins.
	user := &types.UserV2{Kind: types.KindUser, Version: types.V2, Metadata: types.Metadata{Name: username, Namespace: apidefaults.Namespace}, Spec: types.UserSpecV2{
		Roles: roles, Traits: traits,
		OIDCIdentities: []types.ExternalIdentity{{ConnectorID: connector.GetName(), Username: username, UserID: idToken.Subject}},
		CreatedBy:      types.CreatedBy{User: types.UserRef{Name: teleport.UserSystem}, Time: s.auth.GetClock().Now().UTC(), Connector: &types.ConnectorRef{Type: constants.OIDC, ID: connector.GetName(), Identity: username}},
	}}
	existingUser, err := s.auth.Services.GetUser(ctx, username, false)
	if err != nil && !trace.IsNotFound(err) {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
	}
	if existingUser != nil {
		if !user.GetCreatedBy().Connector.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.AlreadyExists("local user %q already exists and is not an OIDC user", username))
		}
		user.SetRevision(existingUser.GetRevision())
		if _, err := s.auth.UpdateUser(ctx, user); err != nil {
			return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
		}
	} else if _, err := s.auth.CreateUser(ctx, user); err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
	}
	if err := s.auth.CallLoginHooks(ctx, user); err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
	}
	userState, err := s.auth.GetUserOrLoginState(ctx, username)
	if err != nil {
		return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
	}
	if req.SSOTestFlow {
		diag.Info.Success = true
		return s.finishOIDCLogin(ctx, diag, diagService, &authclient.OIDCAuthResponse{Req: oidcAuthRequestFromProto(req), Identity: types.ExternalIdentity{ConnectorID: connector.GetName(), Username: username, UserID: idToken.Subject}, Username: username}, nil)
	}
	resp := &authclient.OIDCAuthResponse{Req: oidcAuthRequestFromProto(req), Identity: types.ExternalIdentity{ConnectorID: connector.GetName(), Username: username, UserID: idToken.Subject}, Username: username}
	if req.CreateWebSession {
		resp.Session, err = s.auth.CreateWebSessionFromReq(ctx, NewWebSessionRequest{User: username, Roles: userState.GetRoles(), Traits: userState.GetTraits(), SessionTTL: ttl, LoginTime: s.auth.GetClock().Now().UTC(), LoginIP: req.ClientLoginIP, LoginUserAgent: req.ClientUserAgent, AttestWebSession: true, CreateDeviceWebToken: true, Scope: req.Scope})
		if err != nil {
			return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
		}
	}
	if len(req.SshPublicKey) != 0 || len(req.TlsPublicKey) != 0 {
		resp.Cert, resp.TLSCert, err = s.signOIDCCerts(ctx, req, userState, ttl)
		if err != nil {
			return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
		}
		clusterName, err := s.auth.GetClusterName(ctx)
		if err != nil {
			return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
		}
		hostCA, err := s.auth.GetCertAuthority(ctx, types.CertAuthID{Type: types.HostCA, DomainName: clusterName.GetClusterName()}, false)
		if err != nil {
			return s.finishOIDCLogin(ctx, diag, diagService, nil, trace.Wrap(err))
		}
		resp.HostSigners = append(resp.HostSigners, hostCA)
	}
	if options, err := s.auth.ClientOptionsForLogin(userState); err == nil {
		resp.ClientOptions = options
	}
	diag.Info.Success = true
	return s.finishOIDCLogin(ctx, diag, diagService, resp, nil)
}

func oidcOAuthEndpoint(endpoint oauth2.Endpoint) oauth2.Endpoint {
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	return endpoint
}

func oidcNonceFromState(state string) string {
	hash := sha256.Sum256([]byte(state))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func oidcHTTPContext(ctx context.Context) (context.Context, *http.Client, error) {
	httpClient, err := libdefaults.HTTPClient()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return oidc.ClientContext(ctx, httpClient), httpClient, nil
}

func (s *ossOIDCService) finishOIDCLogin(ctx context.Context, diag *SSODiagContext, diagService SSODiagService, resp *authclient.OIDCAuthResponse, err error) (*authclient.OIDCAuthResponse, error) {
	diag.Info.Error = trace.UserMessage(err)
	diag.WriteToBackend(ctx)
	event := &apievents.UserLogin{Metadata: apievents.Metadata{Type: events.UserLoginEvent}, Method: events.LoginMethodOIDC, ConnectionMetadata: authz.ConnectionMetadata(ctx)}
	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diag.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status.Error, event.Status.UserMessage = trace.Unwrap(err).Error(), err.Error()
	} else {
		event.Code = events.UserSSOLoginCode
		if diag.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginCode
		}
		event.User = resp.Username
	}
	event.Status.Success = err == nil
	if emitErr := s.auth.emitter.EmitAuditEvent(ctx, event); emitErr != nil {
		s.auth.logger.WarnContext(ctx, "Failed to emit OIDC login event", "error", emitErr)
	}
	return resp, trace.Wrap(err)
}

func (s *ossOIDCService) consumeRequest(ctx context.Context, state string) error {
	// These key components must stay in sync with lib/services/local/users.go.
	key := backend.NewKey("web", "connectors", "oidc", "requests", state)
	item, err := s.auth.bk.Get(ctx, key)
	if err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(s.auth.bk.ConditionalDelete(ctx, key, item.Revision))
}

func fetchOIDCUserInfo(ctx context.Context, httpClient *http.Client, endpoint string, token *oauth2.Token) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	token.SetAuthHeader(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, trace.BadParameter("userinfo endpoint returned HTTP %d", resp.StatusCode)
	}
	var userInfo map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&userInfo); err != nil {
		return nil, trace.Wrap(err)
	}
	return userInfo, nil
}

func oidcClaimString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func oidcClaimValues(value interface{}) []string {
	switch v := value.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	case []string:
		return v
	case float64, bool:
		return []string{fmt.Sprint(v)}
	}
	return nil
}

func oidcAuthRequestFromProto(req *types.OIDCAuthRequest) authclient.OIDCAuthRequest {
	return authclient.OIDCAuthRequest{ConnectorID: req.ConnectorID, CSRFToken: req.CSRFToken, SSHPubKey: req.SshPublicKey, TLSPubKey: req.TlsPublicKey, CreateWebSession: req.CreateWebSession, ClientRedirectURL: req.ClientRedirectURL}
}

func (s *ossOIDCService) signOIDCCerts(ctx context.Context, req *types.OIDCAuthRequest, userState services.UserState, ttl time.Duration) ([]byte, []byte, error) {
	return s.auth.CreateSessionCerts(ctx, &SessionCertsRequest{UserState: userState, SessionTTL: ttl, SSHPubKey: req.SshPublicKey, TLSPubKey: req.TlsPublicKey, SSHAttestationStatement: hardwarekey.AttestationStatementFromProto(req.SshAttestationStatement), TLSAttestationStatement: hardwarekey.AttestationStatementFromProto(req.TlsAttestationStatement), Compatibility: req.Compatibility, RouteToCluster: req.RouteToCluster, KubernetesCluster: req.KubernetesCluster, LoginIP: req.ClientLoginIP, Scope: req.Scope})
}

var _ OIDCService = (*ossOIDCService)(nil)
