package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

type DeviceAuthorizationManager struct {
	DeviceAuthorizations map[string]*goidc.DeviceAuthorization
	mu                   sync.RWMutex
	maxSize              int
}

func NewDeviceAuthorizationManager(maxSize int) *DeviceAuthorizationManager {
	return &DeviceAuthorizationManager{
		DeviceAuthorizations: make(map[string]*goidc.DeviceAuthorization),
		maxSize:              maxSize,
	}
}

// Save implements goidc.DeviceAuthorizationManager.
func (m *DeviceAuthorizationManager) Save(_ context.Context, request *goidc.DeviceAuthorization) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.DeviceAuthorizations) >= m.maxSize {
		removeOldest(m.DeviceAuthorizations, func(a *goidc.DeviceAuthorization) int {
			return a.CreatedAtTimestamp
		})
	}

	m.DeviceAuthorizations[request.DeviceCode] = request
	return nil
}

// DeviceAuthorization implements goidc.DeviceAuthorizationManager.
func (m *DeviceAuthorizationManager) DeviceAuthorization(_ context.Context, deviceCode string) (*goidc.DeviceAuthorization, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	da, ok := m.DeviceAuthorizations[deviceCode]
	if !ok {
		return nil, errors.New("entity not found")
	}
	return da, nil
}

// DeviceAuthorizationByUserCode implements goidc.DeviceAuthorizationManager.
func (m *DeviceAuthorizationManager) DeviceAuthorizationByUserCode(_ context.Context, userCode string) (*goidc.DeviceAuthorization, error) {
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
