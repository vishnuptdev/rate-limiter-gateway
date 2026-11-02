package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
)

const (
	maxBody       = 1 << 20  // 1 MiB
	maxImportBody = 10 << 20 // 10 MiB
)

// apiError is rendered as {"error":code,"message":...,"problems":...}.
type apiError struct {
	Status   int
	Code     string
	Message  string
	Problems any
	Extra    map[string]any

	clearCookie bool
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func badRequest(msg string) *apiError {
	return &apiError{Status: http.StatusBadRequest, Code: "bad_request", Message: msg}
}

func notFound(what string) *apiError {
	return &apiError{Status: http.StatusNotFound, Code: "not_found", Message: what + " not found"}
}

func conflict(msg string) *apiError {
	return &apiError{Status: http.StatusConflict, Code: "conflict", Message: msg}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// writeErr renders err; anything that is not an *apiError becomes a
// generic 500 so internal details never leak.
func writeErr(w http.ResponseWriter, err error) {
	var e *apiError
	if !errors.As(err, &e) {
		e = &apiError{Status: http.StatusInternalServerError, Code: "internal", Message: "internal error"}
	}
	body := map[string]any{}
	for k, v := range e.Extra {
		body[k] = v
	}
	body["error"] = e.Code
	body["message"] = e.Message
	if e.Problems != nil {
		body["problems"] = e.Problems
	}
	if e.Status == http.StatusTooManyRequests {
		if ra, ok := e.Extra["retry_after_s"].(int); ok {
			w.Header().Set("Retry-After", strconv.Itoa(ra))
		}
	}
	writeJSON(w, e.Status, body)
}

// decodeJSON reads a single JSON value from r into dst with a size limit,
// unknown-field rejection and a mandatory application/json content type.
// If allowEmpty, an empty body leaves dst untouched.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64, allowEmpty bool) *apiError {
	body := http.MaxBytesReader(w, r.Body, limit)
	defer body.Close()
	var first [1]byte
	n, err := io.ReadFull(body, first[:])
	if n == 0 {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return tooLarge()
		}
		if allowEmpty {
			return nil
		}
		return badRequest("request body required")
	}
	if mt, _, perr := mime.ParseMediaType(r.Header.Get("Content-Type")); perr != nil || mt != "application/json" {
		return &apiError{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Content-Type must be application/json"}
	}
	dec := json.NewDecoder(io.MultiReader(bytes.NewReader(first[:]), body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return tooLarge()
		}
		return badRequest("invalid JSON: " + err.Error())
	}
	if _, err := dec.Token(); err != io.EOF {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return tooLarge()
		}
		return badRequest("invalid JSON: unexpected data after top-level value")
	}
	return nil
}

func tooLarge() *apiError {
	return &apiError{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Message: "request body too large"}
}
