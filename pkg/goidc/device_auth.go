package goidc

import "context"

type DeviceAuthorizationManager interface {
	Save(ctx context.Context, request *DeviceAuthorization) error
	DeviceAuthorization(ctx context.Context, deviceCode string) (*DeviceAuthorization, error)
	DeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*DeviceAuthorization, error)
	Delete(ctx context.Context, deviceCode string) error
}

type DeviceAuthorization struct {
	DeviceCode         string `json:"device_code"`
	UserCode           string `json:"user_code"`
	ClientID           string `json:"client_id"`
	Scopes             string `json:"scope"`
	Authorized         bool   `json:"authorized"`
	Accepted           bool
	CreatedAtTimestamp int `json:"created_at"`
	ExpiresAtTimestamp int `json:"expires_at"`
}
