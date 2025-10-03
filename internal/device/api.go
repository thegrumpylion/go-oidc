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
	if ctx.DeviceAuthorizationVerificationCompleteURI != "" {
		verCompURI = ctx.DeviceAuthorizationVerificationCompleteURI + "?user_code=" + userCode
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
