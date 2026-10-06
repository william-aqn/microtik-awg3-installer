package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	PasswordIterations = 100000
	MinPasswordLength  = 16
	MaxPasswordLength  = 256
	MaxPasswordRequest = 4096
)

func validatePassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < MinPasswordLength || utf8.RuneCountInString(password) > MaxPasswordLength {
		return errors.New("Use a password of 16 to 256 characters")
	}
	nonspace := false
	for _, c := range password {
		if unicode.IsControl(c) {
			return errors.New("Control characters are not allowed in the password")
		}
		nonspace = nonspace || !unicode.IsSpace(c)
	}
	if !nonspace {
		return errors.New("The password must not consist of spaces only")
	}
	return nil
}

func sessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{Name: "awg_session", Value: token, Path: "/", MaxAge: 8 * 3600, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func (a *App) passwordAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		apiError(w, 405, "POST required")
		return
	}
	var input struct {
		Password     string `json:"password"`
		Confirmation string `json:"confirmation"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxPasswordRequest))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&input); e != nil {
		apiError(w, 400, "Invalid password request")
		return
	}
	if e := validatePassword(input.Password); e != nil {
		apiError(w, 400, e.Error())
		return
	}
	if input.Password != input.Confirmation {
		apiError(w, 400, "Passwords do not match")
		return
	}
	saltText := randomID()[:32]
	salt, _ := hex.DecodeString(saltText)
	hash, e := pbkdf2.Key(sha256.New, input.Password, salt, PasswordIterations, 32)
	if e != nil {
		apiError(w, 500, "Cannot derive password hash")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Recheck after hashing: another password change may have revoked this
	// request's session while it was deriving its new hash.
	if !a.demo {
		cookie, err := r.Cookie("awg_session")
		if err != nil || !time.Now().Before(a.sessions[cookie.Value]) {
			apiError(w, 401, "Sign in to the panel")
			return
		}
	}
	if a.busy {
		apiError(w, 409, "Wait for the current operation to finish")
		return
	}
	if a.demo {
		reply(w, 200, map[string]string{"message": "Preview only. No real password was changed."})
		return
	}
	settings := a.s
	settings.PasswordSalt = saltText
	settings.PasswordHash = hex.EncodeToString(hash)
	path := a.configPath
	if path == "" {
		path = filepath.Join(a.s.DataDir, "settings.json")
	}
	if e = writeJSON(path, settings); e != nil {
		apiError(w, 500, "Cannot save password on USB. Your current password and sessions are unchanged.")
		return
	}
	a.s.PasswordSalt = settings.PasswordSalt
	a.s.PasswordHash = settings.PasswordHash
	token := randomID()
	a.sessions = map[string]time.Time{token: time.Now().Add(8 * time.Hour)}
	a.loginAttempts = 0
	a.loginWindow = time.Now()
	sessionCookie(w, r, token)
	reply(w, 200, map[string]string{"message": "Password changed. Other sessions were signed out. Your VPN connection is unchanged."})
}
