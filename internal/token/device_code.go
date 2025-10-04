package token

import (
	"github.com/luikyv/go-oidc/internal/clientutil"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func generateDeviceCodeGrant(ctx oidc.Context, req request) (response, error) {
	client, err := clientutil.Authenticated(ctx, clientutil.TokenAuthnContext)
	if err != nil {
		return response{}, err
	}

	if req.clientID != "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "client_id is required")
	}
	if req.deviceCode != "" {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidRequest, "device_code is required")
	}
	if req.clientID != client.ID {
		return response{}, goidc.NewError(goidc.ErrorCodeInvalidClient, "client_id does not match authenticated client")
	}

	da, err := ctx.DeviceAuthorization(req.deviceCode)
	if err != nil {
		return response{}, goidc.WrapError(goidc.ErrorCodeInvalidGrant, "invalid device_code", err)
	}

	if da.AuthPending {
		return response{}, goidc.NewError(goidc.ErrorCodeAuthPending, "authorization is still pending")
	}
	return response{}, nil
}
