package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"amanah-auth/internal/handler"
	"amanah-auth/internal/repository"
	"amanah-auth/internal/service"
)

// ---------- test harness ----------

type captureNotifier struct {
	mu    sync.Mutex
	codes map[string]string // "dest|purpose" -> kode terakhir
}

func (c *captureNotifier) SendOTP(_ context.Context, _, dest, code, purpose string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.codes[dest+"|"+purpose] = code
	return nil
}
func (c *captureNotifier) code(dest, purpose string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codes[dest+"|"+purpose]
}

type env struct {
	t     *testing.T
	h     http.Handler
	n     *captureNotifier
	clock *time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clock := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	n := &captureNotifier{codes: map[string]string{}}
	svc := service.NewAuth(repository.NewMemory(), n, service.Config{
		JWTSecret: "test-jwt-secret-test-jwt-secret-1234", OTPSecret: "test-otp-secret-test-otp-secret-1234",
		AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour, RefreshTTLRemember: 720 * time.Hour,
		ResetTokenTTL: 10 * time.Minute, OTPTTL: 5 * time.Minute, OTPResendCooldown: 60 * time.Second,
		LockDuration: 15 * time.Minute, OTPMaxAttempts: 5, OTPMaxPerHour: 5, MaxLoginAttempts: 5,
		BcryptCost: bcrypt.MinCost,
	})
	e := &env{t: t, n: n, clock: &clock}
	svc.Now = func() time.Time { return *e.clock }
	e.h = handler.New(svc, slog.New(slog.NewTextHandler(io.Discard, nil))).Routes()
	return e
}

func (e *env) advance(d time.Duration) { *e.clock = e.clock.Add(d) }

func (e *env) do(method, path string, body any, token string) (int, map[string]any) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func dataOf(m map[string]any) map[string]any { d, _ := m["data"].(map[string]any); return d }
func errOf(m map[string]any) map[string]any  { d, _ := m["error"].(map[string]any); return d }
func detail(m map[string]any, k string) any {
	d, _ := errOf(m)["details"].(map[string]any)
	return d[k]
}

func (e *env) expect(got, want int, body map[string]any) {
	e.t.Helper()
	if got != want {
		e.t.Fatalf("status = %d, want %d, body = %v", got, want, body)
	}
}

const (
	pw    = "Rahasia@123"
	email = "budi@domain.com"
	phone = "+6281234567890"
)

func (e *env) register() map[string]any {
	e.t.Helper()
	code, body := e.do("POST", "/api/v1/auth/register", map[string]any{
		"full_name": "Budi Santoso", "email": email, "phone": "0812-3456-7890",
		"password": pw, "confirm_password": pw, "accept_terms": true,
	}, "")
	e.expect(code, 201, body)
	return dataOf(body)
}

// ---------- tests ----------

func TestRegister(t *testing.T) {
	e := newEnv(t)
	res := e.register()
	if res["access_token"] == "" || res["refresh_token"] == "" {
		t.Fatal("token tidak dikembalikan")
	}
	if u := res["user"].(map[string]any); u["phone"] != phone {
		t.Fatalf("phone harus dinormalisasi ke E.164, got %v", u["phone"])
	}

	// duplikat email & nomor dilaporkan sekaligus
	code, body := e.do("POST", "/api/v1/auth/register", map[string]any{
		"full_name": "Orang Lain", "email": "BUDI@domain.com", "phone": "+62 812 3456 7890",
		"password": pw, "confirm_password": pw, "accept_terms": true,
	}, "")
	e.expect(code, 409, body)
	if detail(body, "email") == nil || detail(body, "phone") == nil {
		t.Fatalf("detail harus memuat email & phone: %v", body)
	}

	// validasi input
	code, body = e.do("POST", "/api/v1/auth/register", map[string]any{
		"full_name": "A", "email": "bukan-email", "phone": "123",
		"password": "lemah", "confirm_password": "beda", "accept_terms": false,
	}, "")
	e.expect(code, 422, body)
	for _, f := range []string{"full_name", "email", "phone", "password", "confirm_password", "accept_terms"} {
		if detail(body, f) == nil {
			t.Errorf("harus ada error untuk field %s", f)
		}
	}

	code, body = e.do("POST", "/api/v1/auth/register", nil, "")
	e.expect(code, 400, body) // body kosong => INVALID_JSON
}

func TestLoginEmailAndMe(t *testing.T) {
	e := newEnv(t)
	e.register()

	code, body := e.do("POST", "/api/v1/auth/login", map[string]any{"identifier": "BUDI@domain.com", "password": pw}, "")
	e.expect(code, 200, body)
	access := dataOf(body)["access_token"].(string)

	code, body = e.do("GET", "/api/v1/me", nil, access)
	e.expect(code, 200, body)
	if dataOf(body)["email"] != email {
		t.Fatalf("unexpected me: %v", body)
	}

	code, body = e.do("GET", "/api/v1/me", nil, "")
	e.expect(code, 401, body)
	code, body = e.do("GET", "/api/v1/me", nil, "token.palsu.xxx")
	e.expect(code, 401, body)

	// akun tidak ada & password salah => pesan yang sama
	code, body = e.do("POST", "/api/v1/auth/login", map[string]any{"identifier": "ghost@x.com", "password": pw}, "")
	e.expect(code, 401, body)
	if errOf(body)["code"] != "INVALID_CREDENTIALS" {
		t.Fatalf("unexpected: %v", body)
	}

	code, body = e.do("POST", "/api/v1/auth/login", map[string]any{"identifier": "", "password": ""}, "")
	e.expect(code, 422, body)

	// token kedaluwarsa
	e.advance(16 * time.Minute)
	code, body = e.do("GET", "/api/v1/me", nil, access)
	e.expect(code, 401, body)
	if errOf(body)["code"] != "TOKEN_EXPIRED" {
		t.Fatalf("harus TOKEN_EXPIRED: %v", body)
	}
}

func TestLoginLockout(t *testing.T) {
	e := newEnv(t)
	e.register()
	bad := map[string]any{"identifier": email, "password": "SalahTotal@1"}

	for want := 4; want >= 1; want-- {
		code, body := e.do("POST", "/api/v1/auth/login", bad, "")
		e.expect(code, 401, body)
		if got := detail(body, "attempts_remaining"); got != float64(want) {
			t.Fatalf("attempts_remaining = %v, want %d", got, want)
		}
	}
	code, body := e.do("POST", "/api/v1/auth/login", bad, "") // percobaan ke-5 => terkunci
	e.expect(code, 423, body)

	// password benar pun ditolak saat terkunci
	code, body = e.do("POST", "/api/v1/auth/login", map[string]any{"identifier": email, "password": pw}, "")
	e.expect(code, 423, body)

	e.advance(16 * time.Minute)
	code, body = e.do("POST", "/api/v1/auth/login", map[string]any{"identifier": email, "password": pw}, "")
	e.expect(code, 200, body)
}

func TestRefreshRotationAndLogout(t *testing.T) {
	e := newEnv(t)
	first := e.register()
	rt1 := first["refresh_token"].(string)

	code, body := e.do("POST", "/api/v1/auth/refresh", map[string]any{"refresh_token": rt1}, "")
	e.expect(code, 200, body)
	rt2 := dataOf(body)["refresh_token"].(string)
	if rt1 == rt2 {
		t.Fatal("refresh token harus dirotasi")
	}

	// reuse token lama => ditolak dan seluruh sesi dicabut
	code, body = e.do("POST", "/api/v1/auth/refresh", map[string]any{"refresh_token": rt1}, "")
	e.expect(code, 401, body)
	code, body = e.do("POST", "/api/v1/auth/refresh", map[string]any{"refresh_token": rt2}, "")
	e.expect(code, 401, body)

	// logout
	code, body = e.do("POST", "/api/v1/auth/login", map[string]any{"identifier": email, "password": pw}, "")
	e.expect(code, 200, body)
	rt3 := dataOf(body)["refresh_token"].(string)
	code, body = e.do("POST", "/api/v1/auth/logout", map[string]any{"refresh_token": rt3}, "")
	e.expect(code, 200, body)
	code, body = e.do("POST", "/api/v1/auth/refresh", map[string]any{"refresh_token": rt3}, "")
	e.expect(code, 401, body)
}

func TestLoginWhatsAppOTP(t *testing.T) {
	e := newEnv(t)
	e.register()
	req := map[string]any{"phone": "0812 3456 7890"}

	code, body := e.do("POST", "/api/v1/auth/login/whatsapp/request-otp", req, "")
	e.expect(code, 200, body)
	otp := e.n.code(phone, "login")
	if len(otp) != 6 {
		t.Fatalf("OTP harus 6 digit, got %q", otp)
	}

	// kirim ulang terlalu cepat
	code, body = e.do("POST", "/api/v1/auth/login/whatsapp/request-otp", req, "")
	e.expect(code, 429, body)

	// salah
	verify := func(c string) (int, map[string]any) {
		return e.do("POST", "/api/v1/auth/login/whatsapp/verify-otp", map[string]any{"phone": phone, "otp": c}, "")
	}
	wrong := "000000"
	if otp == wrong {
		wrong = "111111"
	}
	code, body = verify(wrong)
	e.expect(code, 400, body)
	if detail(body, "attempts_remaining") != float64(4) {
		t.Fatalf("unexpected: %v", body)
	}
	code, body = verify("12ab")
	e.expect(code, 422, body)

	// benar
	code, body = verify(otp)
	e.expect(code, 200, body)
	if dataOf(body)["access_token"] == "" {
		t.Fatal("harus mengembalikan token")
	}
	if dataOf(body)["user"].(map[string]any)["phone_verified"] != true {
		t.Fatal("phone harus terverifikasi")
	}

	// OTP sekali pakai
	code, body = verify(otp)
	e.expect(code, 400, body)

	// nomor tidak terdaftar tidak boleh bocor
	code, body = e.do("POST", "/api/v1/auth/login/whatsapp/request-otp", map[string]any{"phone": "081999999999"}, "")
	e.expect(code, 200, body)
	code, body = e.do("POST", "/api/v1/auth/login/whatsapp/request-otp", map[string]any{"phone": "abc"}, "")
	e.expect(code, 422, body)
}

func TestOTPExpired(t *testing.T) {
	e := newEnv(t)
	e.register()
	e.do("POST", "/api/v1/auth/login/whatsapp/request-otp", map[string]any{"phone": phone}, "")
	otp := e.n.code(phone, "login")

	e.advance(5*time.Minute + time.Second)
	code, body := e.do("POST", "/api/v1/auth/login/whatsapp/verify-otp", map[string]any{"phone": phone, "otp": otp}, "")
	e.expect(code, 410, body)
	if errOf(body)["code"] != "OTP_EXPIRED" {
		t.Fatalf("unexpected: %v", body)
	}
}

func TestOTPMaxAttempts(t *testing.T) {
	e := newEnv(t)
	e.register()
	e.do("POST", "/api/v1/auth/login/whatsapp/request-otp", map[string]any{"phone": phone}, "")
	otp := e.n.code(phone, "login")
	wrong := "000000"
	if otp == wrong {
		wrong = "111111"
	}
	for i := 0; i < 5; i++ {
		code, body := e.do("POST", "/api/v1/auth/login/whatsapp/verify-otp", map[string]any{"phone": phone, "otp": wrong}, "")
		e.expect(code, 400, body)
	}
	// setelah 5x salah, kode benar pun ditolak
	code, body := e.do("POST", "/api/v1/auth/login/whatsapp/verify-otp", map[string]any{"phone": phone, "otp": otp}, "")
	e.expect(code, 429, body)

	// minta kode baru setelah cooldown => kode lama tak berlaku, kode baru berlaku
	e.advance(61 * time.Second)
	code, body = e.do("POST", "/api/v1/auth/login/whatsapp/request-otp", map[string]any{"phone": phone}, "")
	e.expect(code, 200, body)
	code, body = e.do("POST", "/api/v1/auth/login/whatsapp/verify-otp",
		map[string]any{"phone": phone, "otp": e.n.code(phone, "login")}, "")
	e.expect(code, 200, body)
}

func TestForgotPasswordFlow(t *testing.T) {
	e := newEnv(t)
	old := e.register()

	// akun tidak ada => tetap 200 (anti enumeration), tapi tidak ada OTP terkirim
	code, body := e.do("POST", "/api/v1/auth/password/forgot", map[string]any{"method": "email", "destination": "ghost@x.com"}, "")
	e.expect(code, 200, body)
	if e.n.code("ghost@x.com", "password_reset") != "" {
		t.Fatal("OTP tidak boleh terkirim ke akun yang tidak ada")
	}

	code, body = e.do("POST", "/api/v1/auth/password/forgot", map[string]any{"method": "sms", "destination": email}, "")
	e.expect(code, 422, body)

	// lewat email
	code, body = e.do("POST", "/api/v1/auth/password/forgot", map[string]any{"method": "email", "destination": email}, "")
	e.expect(code, 200, body)
	otp := e.n.code(email, "password_reset")

	code, body = e.do("POST", "/api/v1/auth/password/verify-otp", map[string]any{"method": "email", "destination": email, "otp": "999999"}, "")
	e.expect(code, 400, body)

	code, body = e.do("POST", "/api/v1/auth/password/verify-otp", map[string]any{"method": "email", "destination": email, "otp": otp}, "")
	e.expect(code, 200, body)
	rt := dataOf(body)["reset_token"].(string)

	// password lemah ditolak, token belum terpakai
	code, body = e.do("POST", "/api/v1/auth/password/reset", map[string]any{"reset_token": rt, "new_password": "lemah", "confirm_password": "lemah"}, "")
	e.expect(code, 422, body)

	// token palsu
	code, body = e.do("POST", "/api/v1/auth/password/reset", map[string]any{"reset_token": "x.y.z", "new_password": "Baru@12345", "confirm_password": "Baru@12345"}, "")
	e.expect(code, 401, body)

	// sukses
	code, body = e.do("POST", "/api/v1/auth/password/reset", map[string]any{"reset_token": rt, "new_password": "Baru@12345", "confirm_password": "Baru@12345"}, "")
	e.expect(code, 200, body)

	// reset token hanya sekali pakai
	code, body = e.do("POST", "/api/v1/auth/password/reset", map[string]any{"reset_token": rt, "new_password": "Lain@12345", "confirm_password": "Lain@12345"}, "")
	e.expect(code, 401, body)

	// sesi lama dicabut, password lama tak berlaku, password baru berlaku
	code, body = e.do("POST", "/api/v1/auth/refresh", map[string]any{"refresh_token": old["refresh_token"]}, "")
	e.expect(code, 401, body)
	code, body = e.do("POST", "/api/v1/auth/login", map[string]any{"identifier": email, "password": pw}, "")
	e.expect(code, 401, body)
	code, body = e.do("POST", "/api/v1/auth/login", map[string]any{"identifier": email, "password": "Baru@12345"}, "")
	e.expect(code, 200, body)
}

func TestForgotPasswordViaWhatsApp(t *testing.T) {
	e := newEnv(t)
	e.register()
	code, body := e.do("POST", "/api/v1/auth/password/forgot", map[string]any{"method": "whatsapp", "destination": "081234567890"}, "")
	e.expect(code, 200, body)
	otp := e.n.code(phone, "password_reset")
	if otp == "" {
		t.Fatal("OTP WhatsApp harus terkirim")
	}
	code, body = e.do("POST", "/api/v1/auth/password/verify-otp", map[string]any{"method": "whatsapp", "destination": phone, "otp": otp}, "")
	e.expect(code, 200, body)
}
