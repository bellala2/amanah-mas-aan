package handler

import (
	"log/slog"
	"net/http"

	"amanah-auth/internal/service"
)

type Handler struct {
	svc *service.Auth
	log *slog.Logger
}

func New(svc *service.Auth, log *slog.Logger) *Handler { return &Handler{svc: svc, log: log} }

type fn func(w http.ResponseWriter, r *http.Request) error

func (h *Handler) wrap(f fn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			h.fail(w, r, err)
		}
	}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, http.StatusOK, "ok", map[string]string{"status": "up"})
	})

	const p = "/api/v1/auth"
	mux.HandleFunc("POST "+p+"/register", h.wrap(h.register)) //mendaftarkan akun baru
	mux.HandleFunc("POST "+p+"/login", h.wrap(h.login)) // buat masuk
	mux.HandleFunc("POST "+p+"/login/whatsapp/request-otp", h.wrap(h.loginWAReq)) // meminta otp via wa
	mux.HandleFunc("POST "+p+"/login/whatsapp/verify-otp", h.wrap(h.loginWAVerify))  // verify otp wa
	mux.HandleFunc("POST "+p+"/password/forgot", h.wrap(h.forgot))  // meminta otp 
	mux.HandleFunc("POST "+p+"/password/verify-otp", h.wrap(h.forgotVerify)) // token hasil otp password
	mux.HandleFunc("POST "+p+"/password/reset", h.wrap(h.reset)) // resert pw
	mux.HandleFunc("POST "+p+"/refresh", h.wrap(h.refresh)) // memperbarui token, biar oengguna tidak login lagi
	mux.HandleFunc("POST "+p+"/logout", h.wrap(h.logout)) // keluar
	mux.Handle("GET /api/v1/me", h.auth(h.wrap(h.me))) // mengambil data profil dri pengguna yang sedang aktif

	return h.recoverer(logging(h.log, secureHeaders(mux)))
}

func meta(r *http.Request) service.ClientMeta {
	m := clientMeta(r)
	return service.ClientMeta{IP: m.IP, UserAgent: m.UserAgent}
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) error {
	var in service.RegisterInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	res, err := h.svc.Register(r.Context(), in, meta(r))
	if err != nil {
		return err
	}
	ok(w, http.StatusCreated, "Registrasi berhasil", res)
	return nil
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) error {
	var in service.LoginInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	res, err := h.svc.Login(r.Context(), in, meta(r))
	if err != nil {
		return err
	}
	ok(w, http.StatusOK, "Login berhasil", res)
	return nil
}

func (h *Handler) loginWAReq(w http.ResponseWriter, r *http.Request) error {
	var in service.PhoneInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	res, err := h.svc.RequestLoginOTP(r.Context(), in)
	if err != nil {
		return err
	}
	ok(w, http.StatusOK, "Jika nomor terdaftar, kode OTP telah dikirim via WhatsApp", res)
	return nil
}

func (h *Handler) loginWAVerify(w http.ResponseWriter, r *http.Request) error {
	var in service.VerifyLoginOTPInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	res, err := h.svc.VerifyLoginOTP(r.Context(), in, meta(r))
	if err != nil {
		return err
	}
	ok(w, http.StatusOK, "Login berhasil", res)
	return nil
}

func (h *Handler) forgot(w http.ResponseWriter, r *http.Request) error {
	var in service.ForgotInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	res, err := h.svc.ForgotPassword(r.Context(), in)
	if err != nil {
		return err
	}
	ok(w, http.StatusOK, "Jika akun terdaftar, kode OTP telah dikirim", res)
	return nil
}

func (h *Handler) forgotVerify(w http.ResponseWriter, r *http.Request) error {
	var in service.VerifyResetOTPInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	res, err := h.svc.VerifyResetOTP(r.Context(), in)
	if err != nil {
		return err
	}
	ok(w, http.StatusOK, "Kode OTP valid", res)
	return nil
}

func (h *Handler) reset(w http.ResponseWriter, r *http.Request) error {
	var in service.ResetPasswordInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	res, err := h.svc.ResetPassword(r.Context(), in, meta(r))
	if err != nil {
		return err
	}
	ok(w, http.StatusOK, "Kata sandi berhasil diubah", res)
	return nil
}

type refreshInput struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handler) refresh(w http.ResponseWriter, r *http.Request) error {
	var in refreshInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	res, err := h.svc.Refresh(r.Context(), in.RefreshToken, meta(r))
	if err != nil {
		return err
	}
	ok(w, http.StatusOK, "Token diperbarui", res)
	return nil
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) error {
	var in refreshInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := h.svc.Logout(r.Context(), in.RefreshToken); err != nil {
		return err
	}
	ok(w, http.StatusOK, "Logout berhasil", nil)
	return nil
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) error {
	ok(w, http.StatusOK, "OK", service.ToDTO(userFrom(r.Context())))
	return nil
}
