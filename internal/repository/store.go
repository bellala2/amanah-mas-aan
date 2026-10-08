package repository

import (
	"context"
	"errors"
	"time"

	"amanah-auth/internal/model"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrEmailTaken    = errors.New("email already registered")
	ErrPhoneTaken    = errors.New("phone already registered")
	ErrUsernameTaken = errors.New("username already taken")
)

// Store adalah satu-satunya pintu ke database. Service hanya bergantung pada interface ini,
// sehingga test bisa memakai implementasi in-memory tanpa database.
type Store interface {
	// Users
	CreateUser(ctx context.Context, u *model.User) error
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	GetUserByIdentifier(ctx context.Context, identifier string) (*model.User, error) // email atau username
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserByPhone(ctx context.Context, phone string) (*model.User, error)
	UpdatePassword(ctx context.Context, userID, hash string) error
	RegisterFailedLogin(ctx context.Context, userID string, max int, lockFor time.Duration, now time.Time) (attempts int, lockedUntil *time.Time, err error)
	ResetFailedLogin(ctx context.Context, userID string) error
	MarkPhoneVerified(ctx context.Context, userID string, at time.Time) error

	// OTP
	CreateOTP(ctx context.Context, o *model.OTP) error // membatalkan OTP aktif sebelumnya (destination+purpose)
	GetLatestOTP(ctx context.Context, destination, purpose string) (*model.OTP, error)
	CountOTPsSince(ctx context.Context, destination, purpose string, since time.Time) (int, error)
	IncrementOTPAttempts(ctx context.Context, id string) (int, error)
	MarkOTPVerified(ctx context.Context, id string, at time.Time) error
	ConsumeOTP(ctx context.Context, id string, at time.Time) error // ErrNotFound jika belum verified / sudah consumed

	// Refresh tokens
	SaveRefreshToken(ctx context.Context, t *model.RefreshToken) error
	GetRefreshToken(ctx context.Context, hash string) (*model.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, hash string, at time.Time) error
	RevokeAllRefreshTokens(ctx context.Context, userID string, at time.Time) error
}
