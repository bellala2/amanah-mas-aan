package model

import "time"

type User struct {
	ID                  string     `db:"id" json:"id"`
	FullName            string     `db:"full_name" json:"full_name"`
	Username            string     `db:"username" json:"username,omitempty"`
	Email               string     `db:"email" json:"email"`
	Phone               string     `db:"phone" json:"phone"`
	PasswordHash        string     `db:"password_hash" json:"-"` // Disembunyikan dari JSON response
	EmailVerifiedAt     *time.Time `db:"email_verified_at" json:"email_verified_at,omitempty"`
	PhoneVerifiedAt     *time.Time `db:"phone_verified_at" json:"phone_verified_at,omitempty"`
	Status              string     `db:"status" json:"status"`
	FailedLoginAttempts int        `db:"failed_login_attempts" json:"failed_login_attempts"`
	LockedUntil         *time.Time `db:"locked_until" json:"locked_until,omitempty"`
	CreatedAt           time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time  `db:"updated_at" json:"updated_at"`
}

type OTP struct {
	ID          string     `db:"id" json:"id"`
	UserID      *string    `db:"user_id" json:"user_id,omitempty"`
	Channel     string     `db:"channel" json:"channel"`         // whatsapp | email
	Destination string     `db:"destination" json:"destination"` // nomor HP atau email
	Purpose     string     `db:"purpose" json:"purpose"`         // login | password_reset
	CodeHash    string     `db:"code_hash" json:"-"`             // Disembunyikan dari JSON response
	Attempts    int        `db:"attempts" json:"attempts"`
	MaxAttempts int        `db:"max_attempts" json:"max_attempts"`
	ExpiresAt   time.Time  `db:"expires_at" json:"expires_at"`
	VerifiedAt  *time.Time `db:"verified_at" json:"verified_at,omitempty"`
	ConsumedAt  *time.Time `db:"consumed_at" json:"consumed_at,omitempty"`
	CreatedAt   time.Time  `db:"created_at" json:"created_at"`
}

type RefreshToken struct {
	ID        string     `db:"id" json:"id"`
	UserID    string     `db:"user_id" json:"user_id"`
	TokenHash string     `db:"token_hash" json:"-"` // Disembunyikan dari JSON response
	ExpiresAt time.Time  `db:"expires_at" json:"expires_at"`
	RevokedAt *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
	UserAgent string     `db:"user_agent" json:"user_agent"`
	IP        string     `db:"ip_address" json:"ip_address"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}