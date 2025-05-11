package goidc

import "context"

type DeviceAuthorizationManager interface {
	Save(ctx context.Context, request *DeviceAuthorizationRequest) error
	DeviceAuthorization(ctx context.Context, deviceCode string) (*DeviceAuthorizationRequest, error)
	DeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*DeviceAuthorizationRequest, error)
	Delete(ctx context.Context, deviceCode string) error
}

type DeviceAuthorizationRequest struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	ClientID   string `json:"client_id"`
	Scopes     string `json:"scope"`
	Status     string `json:"status"`
	UserID     string `json:"user_id"`
}
