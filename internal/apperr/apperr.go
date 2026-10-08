// Package apperr berisi error terstruktur yang dipetakan ke HTTP status + kode error.
package apperr

import (
	"fmt"
	"net/http"
)

type Error struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
	Cause   error // hanya untuk logging, tidak pernah dikirim ke client
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

func New(status int, code, msg string) *Error {
	return &Error{Status: status, Code: code, Message: msg}
}

// With mengembalikan salinan error dengan detail tambahan.
func (e *Error) With(key string, val any) *Error {
	c := *e
	c.Details = make(map[string]any, len(e.Details)+1)
	for k, v := range e.Details {
		c.Details[k] = v
	}
	c.Details[key] = val
	return &c
}

func Validation(fields map[string]string) *Error {
	d := make(map[string]any, len(fields))
	for k, v := range fields {
		d[k] = v
	}
	return &Error{Status: http.StatusUnprocessableEntity, Code: "VALIDATION_ERROR",
		Message: "Data yang dikirim tidak valid", Details: d}
}

func Conflict(fields map[string]string) *Error {
	e := Validation(fields)
	e.Status = http.StatusConflict
	e.Code = "ALREADY_REGISTERED"
	e.Message = "Data sudah terdaftar"
	return e
}

func Unauthorized(code, msg string) *Error { return New(http.StatusUnauthorized, code, msg) }

func Internal(cause error) *Error {
	return &Error{Status: http.StatusInternalServerError, Code: "INTERNAL_ERROR",
		Message: "Terjadi kesalahan pada server", Cause: cause}
}
