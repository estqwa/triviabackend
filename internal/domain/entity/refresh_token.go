package entity

import (
	"time"
)

// RefreshToken представляет собой refresh токен пользователя
type RefreshToken struct {
	ID        uint       `json:"id"`
	UserID    uint       `json:"user_id"`
	Token     string     `json:"token"`
	DeviceID  string     `json:"device_id"`
	IPAddress string     `json:"ip_address"`
	UserAgent string     `json:"user_agent"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	IsExpired bool       `json:"is_expired"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Reason    string     `json:"reason,omitempty"`
}

// NewRefreshToken создает новый refresh токен
func NewRefreshToken(userID uint, token, deviceID, ipAddress, userAgent string, expiresAt time.Time) *RefreshToken {
	return &RefreshToken{
		UserID:    userID,
		Token:     token,
		DeviceID:  deviceID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		IsExpired: false,
	}
}

// IsValid проверяет действительность токена
func (rt *RefreshToken) IsValid() bool {
	return !rt.IsExpired && rt.ExpiresAt.After(time.Now())
}

// SessionInfo возвращает информацию о сессии для отображения пользователю
func (rt *RefreshToken) SessionInfo() map[string]interface{} {
	info := map[string]interface{}{
		"id":         rt.ID,
		"device_id":  rt.DeviceID,
		"ip_address": rt.IPAddress,
		"user_agent": rt.UserAgent,
		"created_at": rt.CreatedAt,
		"expires_at": rt.ExpiresAt,
		"is_expired": rt.IsExpired,
	}

	if rt.RevokedAt != nil {
		info["revoked_at"] = rt.RevokedAt
	}

	if rt.Reason != "" {
		info["reason"] = rt.Reason
	}

	return info
}

// TableName определяет имя таблицы для GORM
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}
