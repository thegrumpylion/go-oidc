package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type DeviceAuthorizationManager struct {
	DeviceAuthorizations map[string]*goidc.DeviceAuthorizationRequest
	mu                   sync.RWMutex
}

// Save implements goidc.DeviceAuthorizationManager.
func (m *DeviceAuthorizationManager) Save(_ context.Context, request *goidc.DeviceAuthorizationRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.DeviceAuthorizations[request.DeviceCode] = request
	return nil
}

// DeviceAuthorization implements goidc.DeviceAuthorizationManager.
func (m *DeviceAuthorizationManager) DeviceAuthorization(_ context.Context, deviceCode string) (*goidc.DeviceAuthorizationRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	da, ok := m.DeviceAuthorizations[deviceCode]
	if !ok {
		return nil, errors.New("entity not found")
	}
	return da, nil
}

// DeviceAuthorizationByUserCode implements goidc.DeviceAuthorizationManager.
func (m *DeviceAuthorizationManager) DeviceAuthorizationByUserCode(_ context.Context, userCode string) (*goidc.DeviceAuthorizationRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, da := range m.DeviceAuthorizations {
		if da.UserCode == userCode {
			return da, nil
		}
	}
	return nil, errors.New("entity not found")
}

// Delete implements goidc.DeviceAuthorizationManager.
func (m *DeviceAuthorizationManager) Delete(_ context.Context, deviceCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.DeviceAuthorizations, deviceCode)
	return nil
}

var _ goidc.DeviceAuthorizationManager = (*DeviceAuthorizationManager)(nil)
