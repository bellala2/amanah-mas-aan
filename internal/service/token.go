package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"amanah-auth/internal/apperr"
	"amanah-auth/internal/model"
)

const (
	tokAccess = "access"
	tokReset  = "password_reset"
)

type claims struct {
	Typ   string `json:"typ"`
	OTPID string `json:"otp,omitempty"`
	jwt.RegisteredClaims
}

type UserDTO struct {
	ID            string    `json:"id"`
	FullName      string    `json:"full_name"`
	Username      string    `json:"username,omitempty"`
	Email         string    `json:"email"`
	Phone         string    `json:"phone"`
	EmailVerified bool      `json:"email_verified"`
	PhoneVerified bool      `json:"phone_verified"`
	CreatedAt     time.Time `json:"created_at"`
}

func ToDTO(u *model.User) UserDTO {
	return UserDTO{ID: u.ID, FullName: u.FullName, Username: u.Username, Email: u.Email, Phone: u.Phone,
		EmailVerified: u.EmailVerifiedAt != nil, PhoneVerified: u.PhoneVerifiedAt != nil, CreatedAt: u.CreatedAt}
}

type AuthResult struct {
	AccessToken  string  `json:"access_token"`
	RefreshToken string  `json:"refresh_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int     `json:"expires_in"`
	User         UserDTO `json:"user"`
}

type ClientMeta struct{ IP, UserAgent string }

func (s *Auth) sign(typ, sub, otpID string, ttl time.Duration) (string, error) {
	now := s.Now()
	c := claims{Typ: typ, OTPID: otpID, RegisteredClaims: jwt.RegisteredClaims{
		Issuer: "amanah-auth", Subject: sub,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(s.cfg.JWTSecret))
}

func (s *Auth) parse(token, typ string) (*claims, error) {
	c := &claims{}
	_, err := jwt.ParseWithClaims(token, c,
		func(*jwt.Token) (any, error) { return []byte(s.cfg.JWTSecret), nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithTimeFunc(s.Now), jwt.WithExpirationRequired())
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, apperr.Unauthorized("TOKEN_EXPIRED", "Token sudah kedaluwarsa")
		}
		return nil, apperr.Unauthorized("INVALID_TOKEN", "Token tidak valid")
	}
	if c.Typ != typ || c.Subject == "" {
		return nil, apperr.Unauthorized("INVALID_TOKEN", "Token tidak valid")
	}
	return c, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (s *Auth) issueTokens(ctx context.Context, u *model.User, refreshTTL time.Duration, meta ClientMeta) (*AuthResult, error) {
	access, err := s.sign(tokAccess, u.ID, "", s.cfg.AccessTTL)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	raw, err := randomToken()
	if err != nil {
		return nil, apperr.Internal(err)
	}
	now := s.Now()
	rt := &model.RefreshToken{UserID: u.ID, TokenHash: hashToken(raw), ExpiresAt: now.Add(refreshTTL),
		UserAgent: meta.UserAgent, IP: meta.IP, CreatedAt: now}
	if err := s.store.SaveRefreshToken(ctx, rt); err != nil {
		return nil, apperr.Internal(err)
	}
	return &AuthResult{AccessToken: access, RefreshToken: raw, TokenType: "Bearer",
		ExpiresIn: int(s.cfg.AccessTTL.Seconds()), User: ToDTO(u)}, nil
}
