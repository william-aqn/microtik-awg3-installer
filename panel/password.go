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

func passwordHash(password string) (string, string, error) {
	saltText := randomID()[:32]
	salt, _ := hex.DecodeString(saltText)
	hash, e := pbkdf2.Key(sha256.New, password, salt, PasswordIterations, 32)
	return saltText, hex.EncodeToString(hash), e
}

// Caller holds a.mu. Publish new credentials only after the USB write succeeds.
func (a *App) savePassword(salt, hash string) error {
	settings := a.s
	settings.PasswordSalt, settings.PasswordHash = salt, hash
	path := a.configPath
	if path == "" {
		path = filepath.Join(a.s.DataDir, "settings.json")
	}
	if e := writeJSON(path, settings); e != nil {
		return errors.New("Cannot save password on USB. Your current password and sessions are unchanged.")
	}
	a.s.PasswordSalt, a.s.PasswordHash = salt, hash
	a.sessions = map[string]time.Time{}
	a.loginAttempts = 0
	a.loginWindow = time.Now()
	return nil
}

// Recovery is exposed ONLY on the root-only Unix control socket, never HTTP.
// The command prints the fresh password to the administrator's terminal only.
func (a *App) resetPassword(w http.ResponseWriter) {
	password := randomID()[:32]
	salt, hash, e := passwordHash(password)
	if e != nil {
		apiError(w, 500, "Cannot derive password hash")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.demo {
		apiError(w, 409, "Password recovery is not available in preview")
		return
	}
	if a.busy {
		apiError(w, 409, "Wait for the current operation to finish, then run the command again")
		return
	}
	if e := a.savePassword(salt, hash); e != nil {
		apiError(w, 500, e.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	reply(w, 200, map[string]string{
		"password": password,
		"message":  "All panel sessions were signed out. VPN is unchanged. Sign in and choose your own password in Settings > Panel access.",
	})
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
	saltText, hash, e := passwordHash(input.Password)
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
	if e = a.savePassword(saltText, hash); e != nil {
		apiError(w, 500, e.Error())
		return
	}
	token := randomID()
	a.sessions[token] = time.Now().Add(8 * time.Hour)
	sessionCookie(w, r, token)
	reply(w, 200, map[string]string{"message": "Password changed. Other sessions were signed out. Your VPN connection is unchanged."})
}
