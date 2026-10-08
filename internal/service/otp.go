package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"amanah-auth/internal/apperr"
	"amanah-auth/internal/model"
	"amanah-auth/internal/repository"
	"amanah-auth/internal/validator"
)

const (
	purposeLogin = "login"
	purposeReset = "password_reset"
	chWhatsApp   = "whatsapp"
	chEmail      = "email"
)

var otpRe = regexp.MustCompile(`^\d{6}$`)

type OTPSent struct {
	Destination string `json:"destination"` // sudah di-mask
	ExpiresIn   int    `json:"expires_in"`  // detik
	ResendIn    int    `json:"resend_in"`   // detik
	DebugOTP    string `json:"debug_otp,omitempty"`
}

// ---------- OTP core ----------

func (s *Auth) hashOTP(purpose, dest, code string) string {
	m := hmac.New(sha256.New, []byte(s.cfg.OTPSecret))
	m.Write([]byte(purpose + "|" + dest + "|" + code))
	return hex.EncodeToString(m.Sum(nil))
}

func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// issueOTP membuat & mengirim OTP baru, dengan cooldown kirim-ulang dan batas per jam.
func (s *Auth) issueOTP(ctx context.Context, userID, channel, dest, purpose string) (string, error) {
	now := s.Now()
	last, err := s.store.GetLatestOTP(ctx, dest, purpose)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return "", apperr.Internal(err)
	}
	if last != nil {
		if wait := last.CreatedAt.Add(s.cfg.OTPResendCooldown).Sub(now); wait > 0 {
			return "", apperr.New(http.StatusTooManyRequests, "OTP_RESEND_COOLDOWN",
				"Tunggu sebentar sebelum meminta kode baru").With("retry_after", ceilSec(wait))
		}
	}
	n, err := s.store.CountOTPsSince(ctx, dest, purpose, now.Add(-time.Hour))
	if err != nil {
		return "", apperr.Internal(err)
	}
	if n >= s.cfg.OTPMaxPerHour {
		return "", apperr.New(http.StatusTooManyRequests, "OTP_RATE_LIMITED",
			"Terlalu banyak permintaan kode. Coba lagi dalam 1 jam.").With("retry_after", 3600)
	}

	code, err := generateCode()
	if err != nil {
		return "", apperr.Internal(err)
	}
	o := &model.OTP{UserID: &userID, Channel: channel, Destination: dest, Purpose: purpose,
		CodeHash: s.hashOTP(purpose, dest, code), MaxAttempts: s.cfg.OTPMaxAttempts,
		ExpiresAt: now.Add(s.cfg.OTPTTL), CreatedAt: now}
	if err := s.store.CreateOTP(ctx, o); err != nil {
		return "", apperr.Internal(err)
	}
	if err := s.notifier.SendOTP(ctx, channel, dest, code, purpose); err != nil {
		return "", apperr.New(http.StatusBadGateway, "OTP_DELIVERY_FAILED", "Gagal mengirim kode OTP. Coba lagi.")
	}
	return code, nil
}

func (s *Auth) sentResponse(dest, code string) *OTPSent {
	r := &OTPSent{Destination: dest, ExpiresIn: int(s.cfg.OTPTTL.Seconds()), ResendIn: int(s.cfg.OTPResendCooldown.Seconds())}
	if s.cfg.DebugOTP {
		r.DebugOTP = code
	}
	return r
}

func errOTPInvalid() *apperr.Error {
	return apperr.New(http.StatusBadRequest, "OTP_INVALID", "Kode OTP tidak sesuai")
}

// verifyOTP memvalidasi kode: format, keberadaan, kedaluwarsa, batas percobaan, kecocokan.
func (s *Auth) verifyOTP(ctx context.Context, dest, purpose, code string) (*model.OTP, error) {
	if !otpRe.MatchString(code) {
		return nil, apperr.Validation(validator.Fields{"otp": "Kode OTP harus 6 digit angka"})
	}
	o, err := s.store.GetLatestOTP(ctx, dest, purpose)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, errOTPInvalid()
	}
	if err != nil {
		return nil, apperr.Internal(err)
	}
	now := s.Now()
	if o.ConsumedAt != nil || o.VerifiedAt != nil {
		return nil, errOTPInvalid()
	}
	if now.After(o.ExpiresAt) {
		return nil, apperr.New(http.StatusGone, "OTP_EXPIRED", "Kode OTP sudah kedaluwarsa. Silakan minta kode baru.")
	}
	if o.Attempts >= o.MaxAttempts {
		return nil, apperr.New(http.StatusTooManyRequests, "OTP_MAX_ATTEMPTS",
			"Terlalu banyak percobaan salah. Silakan minta kode baru.")
	}
	if subtle.ConstantTimeCompare([]byte(s.hashOTP(purpose, dest, code)), []byte(o.CodeHash)) != 1 {
		n, err := s.store.IncrementOTPAttempts(ctx, o.ID)
		if err != nil {
			return nil, apperr.Internal(err)
		}
		return nil, errOTPInvalid().With("attempts_remaining", max(0, o.MaxAttempts-n))
	}
	if err := s.store.MarkOTPVerified(ctx, o.ID, now); err != nil {
		return nil, apperr.Internal(err)
	}
	o.VerifiedAt = &now
	return o, nil
}

func maskPhone(p string) string {
	if len(p) < 9 {
		return p
	}
	return p[:5] + strings.Repeat("*", len(p)-8) + p[len(p)-3:]
}

func maskEmail(e string) string {
	at := strings.IndexByte(e, '@')
	if at < 1 {
		return e
	}
	return e[:1] + "***" + e[at:]
}

// ---------- Login WhatsApp ----------

type PhoneInput struct {
	Phone string `json:"phone"`
}

// RequestLoginOTP selalu membalas sukses meski nomor belum terdaftar (anti user-enumeration).
func (s *Auth) RequestLoginOTP(ctx context.Context, in PhoneInput) (*OTPSent, error) {
	phone, ok := validator.NormalizePhone(in.Phone)
	if !ok {
		return nil, apperr.Validation(validator.Fields{"phone": "Nomor WhatsApp tidak valid"})
	}
	u, err := s.store.GetUserByPhone(ctx, phone)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && u.Status != "active") {
		return s.sentResponse(maskPhone(phone), ""), nil
	}
	if err != nil {
		return nil, apperr.Internal(err)
	}
	code, err := s.issueOTP(ctx, u.ID, chWhatsApp, phone, purposeLogin)
	if err != nil {
		return nil, err
	}
	return s.sentResponse(maskPhone(phone), code), nil
}

type VerifyLoginOTPInput struct {
	Phone string `json:"phone"`
	OTP   string `json:"otp"`
}

func (s *Auth) VerifyLoginOTP(ctx context.Context, in VerifyLoginOTPInput, meta ClientMeta) (*AuthResult, error) {
	phone, ok := validator.NormalizePhone(in.Phone)
	if !ok {
		return nil, apperr.Validation(validator.Fields{"phone": "Nomor WhatsApp tidak valid"})
	}
	o, err := s.verifyOTP(ctx, phone, purposeLogin, in.OTP)
	if err != nil {
		return nil, err
	}
	if err := s.store.ConsumeOTP(ctx, o.ID, s.Now()); err != nil { // sekali pakai
		return nil, errOTPInvalid()
	}
	u, err := s.store.GetUserByPhone(ctx, phone)
	if err != nil || u.Status != "active" {
		return nil, errOTPInvalid()
	}
	now := s.Now()
	_ = s.store.MarkPhoneVerified(ctx, u.ID, now)
	if u.PhoneVerifiedAt == nil {
		u.PhoneVerifiedAt = &now
	}
	_ = s.store.ResetFailedLogin(ctx, u.ID)
	return s.issueTokens(ctx, u, s.cfg.RefreshTTL, meta)
}

// ---------- Lupa password ----------

type ForgotInput struct {
	Method      string `json:"method"`      // email | whatsapp
	Destination string `json:"destination"` // alamat email atau nomor WhatsApp
}

func (s *Auth) normalizeDestination(method, dest string) (string, string, *apperr.Error) {
	switch method {
	case chEmail:
		e := strings.ToLower(strings.TrimSpace(dest))
		if !validator.Email(e) {
			return "", "", apperr.Validation(validator.Fields{"destination": "Format email tidak valid"})
		}
		return e, maskEmail(e), nil
	case chWhatsApp:
		p, ok := validator.NormalizePhone(dest)
		if !ok {
			return "", "", apperr.Validation(validator.Fields{"destination": "Nomor WhatsApp tidak valid"})
		}
		return p, maskPhone(p), nil
	}
	return "", "", apperr.Validation(validator.Fields{"method": "Metode harus 'email' atau 'whatsapp'"})
}

// ForgotPassword selalu membalas sukses meski akun tidak ada (anti user-enumeration).
func (s *Auth) ForgotPassword(ctx context.Context, in ForgotInput) (*OTPSent, error) {
	dest, masked, aerr := s.normalizeDestination(in.Method, in.Destination)
	if aerr != nil {
		return nil, aerr
	}
	var u *model.User
	var err error
	if in.Method == chEmail {
		u, err = s.store.GetUserByEmail(ctx, dest)
	} else {
		u, err = s.store.GetUserByPhone(ctx, dest)
	}
	if errors.Is(err, repository.ErrNotFound) || (err == nil && u.Status != "active") {
		return s.sentResponse(masked, ""), nil
	}
	if err != nil {
		return nil, apperr.Internal(err)
	}
	code, err := s.issueOTP(ctx, u.ID, in.Method, dest, purposeReset)
	if err != nil {
		return nil, err
	}
	return s.sentResponse(masked, code), nil
}

type VerifyResetOTPInput struct {
	Method      string `json:"method"`
	Destination string `json:"destination"`
	OTP         string `json:"otp"`
}

type ResetTokenResult struct {
	ResetToken string `json:"reset_token"`
	ExpiresIn  int    `json:"expires_in"`
}

// VerifyResetOTP menukar OTP valid dengan reset_token berumur pendek (JWT, sekali pakai).
func (s *Auth) VerifyResetOTP(ctx context.Context, in VerifyResetOTPInput) (*ResetTokenResult, error) {
	dest, _, aerr := s.normalizeDestination(in.Method, in.Destination)
	if aerr != nil {
		return nil, aerr
	}
	o, err := s.verifyOTP(ctx, dest, purposeReset, in.OTP)
	if err != nil {
		return nil, err
	}
	if o.UserID == nil {
		return nil, errOTPInvalid()
	}
	tok, err := s.sign(tokReset, *o.UserID, o.ID, s.cfg.ResetTokenTTL)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	return &ResetTokenResult{ResetToken: tok, ExpiresIn: int(s.cfg.ResetTokenTTL.Seconds())}, nil
}

type ResetPasswordInput struct {
	ResetToken      string `json:"reset_token"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// ResetPassword mengganti password lalu langsung login ("Simpan Kata Sandi & Masuk").
func (s *Auth) ResetPassword(ctx context.Context, in ResetPasswordInput, meta ClientMeta) (*AuthResult, error) {
	c, err := s.parse(in.ResetToken, tokReset)
	if err != nil {
		return nil, err
	}
	f := validator.Fields{}
	if msg := validator.Password(in.NewPassword); msg != "" {
		f.Add("new_password", msg)
	}
	if in.NewPassword != in.ConfirmPassword {
		f.Add("confirm_password", "Konfirmasi kata sandi tidak sama")
	}
	if len(f) > 0 { // validasi sebelum token dikonsumsi, user bisa mencoba lagi
		return nil, apperr.Validation(f)
	}
	u, err := s.store.GetUserByID(ctx, c.Subject)
	if err != nil {
		return nil, errInvalidToken()
	}
	if err := s.store.ConsumeOTP(ctx, c.OTPID, s.Now()); err != nil {
		return nil, errInvalidToken() // sudah dipakai
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), s.cfg.BcryptCost)
	if err != nil {
		return nil, apperr.Internal(err)
	}
	if err := s.store.UpdatePassword(ctx, u.ID, string(hash)); err != nil {
		return nil, apperr.Internal(err)
	}
	_ = s.store.RevokeAllRefreshTokens(ctx, u.ID, s.Now()) // putuskan semua sesi lama
	return s.issueTokens(ctx, u, s.cfg.RefreshTTL, meta)
}
