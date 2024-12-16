package test

import (
	"context"

	"github.com/wrale/oauth2-device-proxy/internal/deviceflow"
)

// MockFlow provides a full implementation of deviceflow.Flow for testing
type MockFlow struct {
	// Common test functions that can be overridden
	CheckHealthFunc       func(ctx context.Context) error
	RequestDeviceCodeFunc func(ctx context.Context, clientID string, scope string) (*deviceflow.DeviceCode, error)
	GetDeviceCodeFunc     func(ctx context.Context, deviceCode string) (*deviceflow.DeviceCode, error)
	CheckDeviceCodeFunc   func(ctx context.Context, deviceCode string) (*deviceflow.TokenResponse, error)
	VerifyUserCodeFunc    func(ctx context.Context, userCode string) (*deviceflow.DeviceCode, error)
	CompleteAuthFunc      func(ctx context.Context, deviceCode string, token *deviceflow.TokenResponse) error
}

// Ensure MockFlow implements Flow interface
var _ deviceflow.Flow = (*MockFlow)(nil)

// CheckHealth implements deviceflow.Flow
func (m *MockFlow) CheckHealth(ctx context.Context) error {
	if m.CheckHealthFunc != nil {
		return m.CheckHealthFunc(ctx)
	}
	return nil
}

// RequestDeviceCode implements deviceflow.Flow
func (m *MockFlow) RequestDeviceCode(ctx context.Context, clientID string, scope string) (*deviceflow.DeviceCode, error) {
	if m.RequestDeviceCodeFunc != nil {
		return m.RequestDeviceCodeFunc(ctx, clientID, scope)
	}
	return nil, nil
}

// GetDeviceCode implements deviceflow.Flow
func (m *MockFlow) GetDeviceCode(ctx context.Context, deviceCode string) (*deviceflow.DeviceCode, error) {
	if m.GetDeviceCodeFunc != nil {
		return m.GetDeviceCodeFunc(ctx, deviceCode)
	}
	return nil, nil
}

// CheckDeviceCode implements deviceflow.Flow
func (m *MockFlow) CheckDeviceCode(ctx context.Context, deviceCode string) (*deviceflow.TokenResponse, error) {
	if m.CheckDeviceCodeFunc != nil {
		return m.CheckDeviceCodeFunc(ctx, deviceCode)
	}
	return nil, nil
}

// VerifyUserCode implements deviceflow.Flow
func (m *MockFlow) VerifyUserCode(ctx context.Context, userCode string) (*deviceflow.DeviceCode, error) {
	if m.VerifyUserCodeFunc != nil {
		return m.VerifyUserCodeFunc(ctx, userCode)
	}
	return nil, nil
}

// CompleteAuthorization implements deviceflow.Flow
func (m *MockFlow) CompleteAuthorization(ctx context.Context, deviceCode string, token *deviceflow.TokenResponse) error {
	if m.CompleteAuthFunc != nil {
		return m.CompleteAuthFunc(ctx, deviceCode, token)
	}
	return nil
}
