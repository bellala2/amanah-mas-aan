package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Env         string
	Port        string
	DatabaseURL string
	JWTSecret   string
	OTPSecret   string

	AccessTTL          time.Duration
	RefreshTTL         time.Duration
	RefreshTTLRemember time.Duration
	ResetTokenTTL      time.Duration
	OTPTTL             time.Duration
	OTPResendCooldown  time.Duration
	LockDuration       time.Duration

	OTPMaxAttempts   int
	OTPMaxPerHour    int
	MaxLoginAttempts int
	BcryptCost       int
	DebugOTP         bool
}

func Load() (*Config, error) {
	c := &Config{
		Env:         get("APP_ENV", "development"),
		Port:        get("PORT", "8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		JWTSecret:   os.Getenv("JWT_SECRET"),
		OTPSecret:   os.Getenv("OTP_SECRET"),

		AccessTTL:          dur("ACCESS_TTL", 15*time.Minute),
		RefreshTTL:         dur("REFRESH_TTL", 24*time.Hour),
		RefreshTTLRemember: dur("REFRESH_TTL_REMEMBER", 720*time.Hour),
		ResetTokenTTL:      dur("RESET_TOKEN_TTL", 10*time.Minute),
		OTPTTL:             dur("OTP_TTL", 5*time.Minute),
		OTPResendCooldown:  dur("OTP_RESEND_COOLDOWN", 60*time.Second),
		LockDuration:       dur("LOCK_DURATION", 15*time.Minute),

		OTPMaxAttempts:   num("OTP_MAX_ATTEMPTS", 5),
		OTPMaxPerHour:    num("OTP_MAX_PER_HOUR", 5),
		MaxLoginAttempts: num("MAX_LOGIN_ATTEMPTS", 5),
		BcryptCost:       num("BCRYPT_COST", 12),
		DebugOTP:         get("DEBUG_OTP", "false") == "true",
	}
	if c.DatabaseURL == "" {
		return nil, errors.New("DATABASE_URL wajib diisi")
	}
	if len(c.JWTSecret) < 32 || len(c.OTPSecret) < 32 {
		return nil, errors.New("JWT_SECRET dan OTP_SECRET wajib diisi minimal 32 karakter")
	}
	if c.Env == "production" && c.DebugOTP {
		return nil, errors.New("DEBUG_OTP tidak boleh aktif di production")
	}
	return c, nil
}

func get(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func num(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func dur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
