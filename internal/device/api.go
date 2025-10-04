package device

import (
	"net/http"

	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func RegisterHandlers(router *http.ServeMux, config *oidc.Configuration, middlewares ...goidc.MiddlewareFunc) {
	if config.DeviceAuthorizationIsEnabled {
		router.Handle(
			"POST "+config.EndpointPrefix+config.EndpointDeviceAuthorization,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleCreate), middlewares...),
		)
		router.Handle(
			"GET "+config.EndpointPrefix+config.DeviceAuthorizationVerificationURI,
			goidc.ApplyMiddlewares(oidc.Handler(config, handleVerify), middlewares...),
		)
	}
}

func handleCreate(ctx oidc.Context) {
	req := newRequest(ctx.Request)

	client, oauthErr := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if oauthErr != nil {
		ctx.WriteError(oauthErr)
		return
	}

	if !clientutil.AreScopesAllowed(client, ctx.Scopes, req.scopes) {
		err := goidc.NewError(goidc.ErrorCodeInvalidScope, "invalid scope")
		ctx.WriteError(err)
		return
	}

	deviceCode := generateDeviceCode()
	userCode, err := generateUserCode(ctx.DeviceAuthorizationUserCodeCharset, ctx.DeviceAuthorizationUserCodeLength)
	if err != nil {
		err = goidc.WrapError(goidc.ErrorCodeInternalError, "could not generate user code", err)
		ctx.WriteError(err)
		return
	}

	da := &goidc.DeviceAuthorization{
		DeviceCode:         deviceCode,
		UserCode:           userCode,
		ClientID:           client.ID,
		Scopes:             req.scopes,
		CreatedAtTimestamp: timeutil.TimestampNow(),
		ExpiresAtTimestamp: timeutil.TimestampNow() + ctx.DeviceAuthorizationLifetimeSeconds,
	}
	if err := ctx.SaveDeviceAuthorization(da); err != nil {
		err = goidc.WrapError(goidc.ErrorCodeInternalError, "could not save device authorization", err)
		ctx.WriteError(err)
		return
	}

	verCompURI := ""
	if ctx.DeviceAuthorizationEnableVerificationCompleteURI {
		verCompURI = ctx.DeviceAuthorizationVerificationURI + "?user_code=" + userCode
	}
	resp := response{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         ctx.DeviceAuthorizationVerificationURI,
		VerificationURIComplete: verCompURI,
		ExpiresIn:               ctx.DeviceAuthorizationLifetimeSeconds,
		Interval:                ctx.DeviceAuthorizationPollIntervalSeconds,
	}

	if err := ctx.Write(resp, http.StatusOK); err != nil {
		ctx.WriteError(err)
	}
}

func handleVerify(ctx oidc.Context) {
	// check if we have a user_code in the query parameters
	userCode := ctx.Request.URL.Query().Get("user_code")
	var err error

	if userCode == "" {
		userCode, err = ctx.HandleDeviceAuthorizationFunc(ctx.Request)
		if err != nil {
			err = goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not handle device authorization", err)
			ctx.WriteError(err)
			return
		}
	}

	// TODO: should we error on empty userCode here? the db lookup will fail anyway
	da, err := ctx.DeviceAuthorizationByUserCode(userCode)
	if err != nil {
		err = goidc.WrapError(goidc.ErrorCodeInvalidRequest, "could not fetch device authorization", err)
		ctx.WriteError(err)
		return
	}

	// validate
	if da.ExpiresAtTimestamp < timeutil.TimestampNow() {
		err := goidc.NewError(goidc.ErrorCodeExpiredToken, "expired user code")
		ctx.WriteError(err)
		return
	}
}
