package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"amanah-auth/internal/apperr"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ok(w http.ResponseWriter, status int, message string, data any) {
	writeJSON(w, status, map[string]any{"success": true, "message": message, "data": data})
}

// fail menerjemahkan error apa pun menjadi response JSON seragam.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		ae = apperr.Internal(err)
	}
	if ae.Status >= 500 {
		h.log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	}
	if ra, isInt := ae.Details["retry_after"].(int); isInt {
		w.Header().Set("Retry-After", strconv.Itoa(ra))
	}
	body := map[string]any{"code": ae.Code, "message": ae.Message}
	if len(ae.Details) > 0 {
		body["details"] = ae.Details
	}
	writeJSON(w, ae.Status, map[string]any{"success": false, "error": body})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return apperr.New(http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Ukuran request terlalu besar")
		}
		return apperr.New(http.StatusBadRequest, "INVALID_JSON", "Body request bukan JSON yang valid")
	}
	return nil
}
