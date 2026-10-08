package service

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"amanah-auth/internal/apperr"
	"amanah-auth/internal/model"
	"amanah-auth/internal/repository"
	"amanah-auth/internal/validator"
)

type Config struct {
	JWTSecret, OTPSecret string

	AccessTTL, RefreshTTL, RefreshTTLRemember, ResetTokenTTL time.Duration
	OTPTTL, OTPResendCooldown, LockDuration                  time.Duration

	OTPMaxAttempts, OTPMaxPerHour, MaxLoginAttempts, BcryptCost int
	DebugOTP                                                    bool
}

type Auth struct {
	store     repository.Store
	notifier  Notifier
	cfg       Config
	dummyHash []byte
	Now       func() time.Time // dapat di-override di test
}

func NewAuth(store repository.Store, n Notifier, cfg Config) *Auth {
	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = bcrypt.DefaultCost
	}
	dh, _ := bcrypt.GenerateFromPassword([]byte("dummy-password"), cfg.BcryptCost)
	return &Auth{store: store, notifier: n, cfg: cfg, dummyHash: dh, Now: time.Now}
}

// ---------- error helpers ----------

func errInvalidCreds() *apperr.Error {
	return apperr.Unauthorized("INVALID_CREDENTIALS", "Email/username atau kata sandi salah")
}
func errInvalidToken() *apperr.Error {
	return apperr.Unauthorized("INVALID_TOKEN", "Token tidak valid atau sudah tidak berlaku")
}
func errLocked(d time.Duration) *apperr.Error {
	return apperr.New(http.StatusLocked, "ACCOUNT_LOCKED",
		"Akun dikunci sementara karena terlalu banyak percobaan gagal").With("retry_after", ceilSec(d))
}
func ceilSec(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	return int((d + time.Second - 1) / time.Second)
}

// ---------- Register ----------

type RegisterInput struct {
	FullName        string `json:"full_name"`
	Username        string `json:"username"`
	Email           string `json:"email"`
	Phone           string `json:"phone"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	AcceptTerms     bool   `json:"accept_terms"`
}

func (s *Auth) Register(ctx context.Context, in RegisterInput, meta ClientMeta) (*AuthResult, error) {
	f := validator.Fields{}
	name := strings.TrimSpace(in.FullName)
	if n := len([]rune(name)); n < 3 || n > 100 {
		f.Add("full_name", "Nama lengkap harus 3-100 karakter")
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if !validator.Email(email) {
		f.Add("email", "Format email tidak valid")
	}
	phone, okPhone := validator.NormalizePhone(in.Phone)
	if !okPhone {
		f.Add("phone", "Nomor WhatsApp tidak valid")
	}
	username := strings.ToLower(strings.TrimSpace(in.Username))
	if username != "" && !validator.Username(username) {
		f.Add("username", "Username 3-30 karakter: huruf kecil, angka, titik, atau underscore")
	}
	if msg := validator.Password(in.Password); msg != "" {
		f.Add("password", msg)
	}
	if in.Password != in.ConfirmPassword {
		f.Add("confirm_password", "Konfirmasi kata sandi tidak sama")
	}
	if !in.AcceptTerms {
		f.Add("accept_terms", "Anda harus menyetujui Syarat & Ketentuan dan Kebijakan Privasi")
	}
	if len(f) > 0 {
		return nil, apperr.Validation(f)
	}

	// Pre-check supaya email & nomor yang sama-sama terdaftar dilaporkan sekaligus (sesuai UI).
	dup := validator.Fields{}
	if _, err := s.store.GetUserByEmail(ctx, email); err == nil {
		dup.Add("email", "Email sudah terdaftar. Gunakan email lain atau masuk.")
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, apperr.Internal(err)
	}
	if _, err := s.store.GetUserByPhone(ctx, phone); err == nil {
		dup.Add("phone", "Nomor WhatsApp sudah terdaftar. Gunakan nomor lain.")
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, apperr.Internal(err)
	}
	if len(dup) > 0 {
		return nil, apperr.Conflict(dup)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), s.cfg.BcryptCost)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	u := &model.User{FullName: name, Username: username, Email: email, Phone: phone, PasswordHash: string(hash)}
	if err := s.store.CreateUser(ctx, u); err != nil {
		// Race condition: lolos pre-check tapi kalah di unique constraint.
		switch {
		case errors.Is(err, repository.ErrEmailTaken):
			return nil, apperr.Conflict(validator.Fields{"email": "Email sudah terdaftar. Gunakan email lain atau masuk."})
		case errors.Is(err, repository.ErrPhoneTaken):
			return nil, apperr.Conflict(validator.Fields{"phone": "Nomor WhatsApp sudah terdaftar. Gunakan nomor lain."})
		case errors.Is(err, repository.ErrUsernameTaken):
			return nil, apperr.Conflict(validator.Fields{"username": "Username sudah dipakai"})
		}
		return nil, apperr.Internal(err)
	}
	return s.issueTokens(ctx, u, s.cfg.RefreshTTL, meta)
}

// ---------- Login (email / username + password) ----------

type LoginInput struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

func (s *Auth) Login(ctx context.Context, in LoginInput, meta ClientMeta) (*AuthResult, error) {
	f := validator.Fields{}
	ident := strings.ToLower(strings.TrimSpace(in.Identifier))
	if ident == "" {
		f.Add("identifier", "Email atau username wajib diisi")
	}
	if in.Password == "" {
		f.Add("password", "Kata sandi wajib diisi")
	}
	if len(f) > 0 {
		return nil, apperr.Validation(f)
	}

	u, err := s.store.GetUserByIdentifier(ctx, ident)
	if errors.Is(err, repository.ErrNotFound) {
		// samakan waktu respons agar akun yang tidak ada tidak bisa dibedakan lewat timing
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(in.Password))
		return nil, errInvalidCreds()
	}
	if err != nil {
		return nil, apperr.Internal(err)
	}

	now := s.Now()
	if u.LockedUntil != nil && now.After(*u.LockedUntil) { // kunci sudah habis
		if err := s.store.ResetFailedLogin(ctx, u.ID); err != nil {
			return nil, apperr.Internal(err)
		}
		u.FailedLoginAttempts, u.LockedUntil = 0, nil
	}
	if u.LockedUntil != nil {
		return nil, errLocked(u.LockedUntil.Sub(now))
	}
	if u.Status != "active" {
		return nil, apperr.New(http.StatusForbidden, "ACCOUNT_DISABLED", "Akun tidak aktif. Hubungi dukungan.")
	}

	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) != nil {
		attempts, lockedUntil, err := s.store.RegisterFailedLogin(ctx, u.ID, s.cfg.MaxLoginAttempts, s.cfg.LockDuration, now)
		if err != nil {
			return nil, apperr.Internal(err)
		}
		if lockedUntil != nil && lockedUntil.After(now) {
			return nil, errLocked(lockedUntil.Sub(now))
		}
		return nil, errInvalidCreds().
			With("attempts_remaining", max(0, s.cfg.MaxLoginAttempts-attempts)).
			With("max_attempts", s.cfg.MaxLoginAttempts)
	}

	if u.FailedLoginAttempts > 0 {
		if err := s.store.ResetFailedLogin(ctx, u.ID); err != nil {
			return nil, apperr.Internal(err)
		}
	}
	ttl := s.cfg.RefreshTTL
	if in.RememberMe {
		ttl = s.cfg.RefreshTTLRemember
	}
	return s.issueTokens(ctx, u, ttl, meta)
}

// ---------- Session ----------

func (s *Auth) Refresh(ctx context.Context, raw string, meta ClientMeta) (*AuthResult, error) {
	if raw == "" {
		return nil, apperr.Validation(validator.Fields{"refresh_token": "Refresh token wajib diisi"})
	}
	rt, err := s.store.GetRefreshToken(ctx, hashToken(raw))
	if errors.Is(err, repository.ErrNotFound) {
		return nil, errInvalidToken()
	}
	if err != nil {
		return nil, apperr.Internal(err)
	}
	now := s.Now()
	if rt.RevokedAt != nil {
		// Token yang sudah dirotasi dipakai lagi => kemungkinan dicuri. Cabut semua sesi user.
		_ = s.store.RevokeAllRefreshTokens(ctx, rt.UserID, now)
		return nil, errInvalidToken()
	}
	if now.After(rt.ExpiresAt) {
		return nil, errInvalidToken()
	}
	u, err := s.store.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, errInvalidToken()
	}
	if err := s.store.RevokeRefreshToken(ctx, rt.TokenHash, now); err != nil {
		return nil, apperr.Internal(err)
	}
	return s.issueTokens(ctx, u, rt.ExpiresAt.Sub(now), meta) // rotasi, masa berlaku sisa tetap
}

func (s *Auth) Logout(ctx context.Context, raw string) error {
	if raw == "" {
		return apperr.Validation(validator.Fields{"refresh_token": "Refresh token wajib diisi"})
	}
	if err := s.store.RevokeRefreshToken(ctx, hashToken(raw), s.Now()); err != nil {
		return apperr.Internal(err)
	}
	return nil // idempotent
}

// Authenticate memvalidasi access token dan mengembalikan user.
func (s *Auth) Authenticate(ctx context.Context, token string) (*model.User, error) {
	c, err := s.parse(token, tokAccess)
	if err != nil {
		return nil, err
	}
	u, err := s.store.GetUserByID(ctx, c.Subject)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && u.Status != "active") {
		return nil, apperr.Unauthorized("INVALID_TOKEN", "Token tidak valid")
	}
	if err != nil {
		return nil, apperr.Internal(err)
	}
	return u, nil
}
