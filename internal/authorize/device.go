package authorize

import (
	"slices"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

type deviceResponse struct {
	DeviceCode              string `json:"device_code,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
	Interval                int    `json:"interval,omitempty"`
}

func initDeviceAuth(ctx oidc.Context, req request) (deviceResponse, error) {
	if req.ClientID == "" {
		return deviceResponse{}, goidc.NewError(goidc.ErrorCodeInvalidClient, "invalid client_id")
	}

	// authenticate the client if needed
	c, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		return deviceResponse{}, goidc.WrapError(goidc.ErrorCodeInvalidClient, "invalid client_id", err)
	}

	// check that the client is allowed to call the device code auth endpoint.
	if !slices.ContainsFunc(c.GrantTypes, func(gt goidc.GrantType) bool {
		return gt == goidc.GrantDeviceCode
	}) {
		return deviceResponse{}, goidc.NewError(goidc.ErrorCodeInvalidClient, "client not allowed")
	}

	as, err := initDeviceAuthnSession(ctx, req, c)
	if err != nil {
		return deviceResponse{}, err
	}

	// store the session here. needed by token and device endpoints.
	if err := ctx.SaveAuthnSession(as); err != nil {
		return deviceResponse{}, err
	}

	verURI := ctx.Host + ctx.EndpointPrefix + ctx.DeviceAuthorizationEndpoint
	verCompURI := ""
	if ctx.DeviceAuthorizationEnableVerificationCompleteURI {
		verCompURI = verURI + "?user_code=" + as.UserCode
	}
	resp := deviceResponse{
		DeviceCode:              as.DeviceCode,
		UserCode:                as.UserCode,
		VerificationURI:         verURI,
		VerificationURIComplete: verCompURI,
		ExpiresIn:               ctx.DeviceAuthorizationLifetimeSeconds,
		Interval:                ctx.DeviceAuthorizationPollIntervalSeconds,
	}

	return resp, nil
}

func initDeviceAuthnSession(ctx oidc.Context, req request, client *goidc.Client) (*goidc.AuthnSession, error) {
	as := newAuthnSession(req.AuthorizationParameters, client)
	as.DeviceCode = strutil.Random(32)
	as.UserCode = strutil.RandomFromCharset(ctx.DeviceAuthorizationUserCodeLength, ctx.DeviceAuthorizationUserCodeCharset)
	as.ExpiresAtTimestamp = timeutil.TimestampNow() + ctx.DeviceAuthorizationLifetimeSeconds
	as.AuthorizationPending = true
	// TODO: other fields, validation here?
	return as, nil
}
