package handler

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"amanah-auth/internal/apperr"
	"amanah-auth/internal/model"
)

type ctxKey struct{}

func userFrom(ctx context.Context) *model.User {
	u, _ := ctx.Value(ctxKey{}).(*model.User)
	return u
}

// auth memvalidasi header "Authorization: Bearer <access_token>".
func (h *Handler) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(hdr) <= len(prefix) || !strings.EqualFold(hdr[:len(prefix)], prefix) {
			h.fail(w, r, apperr.Unauthorized("UNAUTHENTICATED", "Authorization Bearer token wajib disertakan"))
			return
		}
		u, err := h.svc.Authenticate(r.Context(), strings.TrimSpace(hdr[len(prefix):]))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

func clientMeta(r *http.Request) (m struct{ IP, UserAgent string }) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// Bila di belakang reverse proxy tepercaya, ganti dengan X-Forwarded-For/X-Real-IP.
	m.IP, m.UserAgent = host, r.UserAgent()
	return
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Info("http", "method", r.Method, "path", r.URL.Path, "status", rec.status, "ms", time.Since(start).Milliseconds())
	})
}

func (h *Handler) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				h.log.Error("panic", "path", r.URL.Path, "panic", rec)
				h.fail(w, r, apperr.Internal(nil))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store") // response berisi token/OTP
		next.ServeHTTP(w, r)
	})
}
