package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func recoveryRequest(a *App, method string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.serveControl(w, httptest.NewRequest(method, "/reset-password", nil))
	return w
}

func TestLocalPasswordRecoveryPreservesVPNAndRevokesEverySession(t *testing.T) {
	a, cookie := passwordApp(t)
	old := a.s
	state := a.state
	// Recovery must not touch the on-disk profile, tunnel intent or Geo data.
	for _, name := range []string{"profiles.json", "tunnel.json", "state.json"} {
		if e := os.WriteFile(filepath.Join(a.s.DataDir, name), []byte("untouched"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	a.loginAttempts = 50
	w := recoveryRequest(a, "POST")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code)
	}
	var result struct{ Password, Message string }
	if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if b, e := hex.DecodeString(result.Password); e != nil || len(b) != 16 || validatePassword(result.Password) != nil {
		t.Fatal("Recovery did not return a fresh 128-bit password")
	}
	r := httptest.NewRequest("GET", "/api/state", nil)
	r.AddCookie(cookie)
	if a.authorized(r) || len(a.sessions) != 0 || len(w.Result().Cookies()) != 0 || a.loginAttempts != 0 {
		t.Fatal("Recovery retained a session or login lockout")
	}
	var saved Settings
	if e := readJSON(a.configPath, &saved); e != nil {
		t.Fatal(e)
	}
	if saved.PasswordHash == old.PasswordHash || saved.PasswordSalt == old.PasswordSalt {
		t.Fatal("Recovery did not rotate credentials")
	}
	unchanged := saved
	unchanged.PasswordHash, unchanged.PasswordSalt = old.PasswordHash, old.PasswordSalt
	if !reflect.DeepEqual(unchanged, old) || !reflect.DeepEqual(a.state, state) || a.busy || a.message != "" || a.lastError != "" {
		t.Fatal("Recovery changed controller state")
	}
	for _, name := range []string{"profiles.json", "tunnel.json", "state.json"} {
		b, _ := os.ReadFile(filepath.Join(a.s.DataDir, name))
		if string(b) != "untouched" {
			t.Fatal("Recovery changed " + name)
		}
	}
	settings, _ := os.ReadFile(a.configPath)
	if strings.Contains(string(settings), result.Password) || strings.Contains(w.Body.String(), saved.RouterPassword) {
		t.Fatal("Recovery leaked a credential")
	}
	if request(a, "POST", "/api/login", `{"password":"testing-panel-password"}`, "router.test", "http://router.test", nil).Code != 401 {
		t.Fatal("Old password still accepted")
	}
	body, _ := json.Marshal(map[string]string{"password": result.Password})
	fresh := testApp()
	fresh.s = saved
	for _, app := range []*App{a, fresh} {
		if request(app, "POST", "/api/login", string(body), "router.test", "http://router.test", nil).Code != 200 {
			t.Fatal("Reset password rejected in memory or after restart")
		}
	}
	w = recoveryRequest(a, "POST")
	var next struct{ Password string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &next) != nil || next.Password == result.Password {
		t.Fatal("Repeated recovery did not generate a new password")
	}
}

func TestPasswordRecoveryIsUnavailableOnPublicHTTP(t *testing.T) {
	a, cookie := passwordApp(t)
	before, _ := os.ReadFile(a.configPath)
	for _, path := range []string{"/reset-password", "/api/reset-password", "/api/control/reset-password"} {
		for _, method := range []string{"GET", "POST"} {
			for _, session := range []*http.Cookie{nil, cookie} {
				w := request(a, method, path, "{}", "router.test", "http://router.test", session)
				if w.Code < 400 || strings.Contains(w.Body.String(), `"password":`) {
					t.Fatal("Public HTTP exposed password recovery", path, w.Code)
				}
			}
		}
	}
	if w := recoveryRequest(a, "GET"); w.Code != 405 {
		t.Fatal("GET changed credentials")
	}
	after, _ := os.ReadFile(a.configPath)
	if string(before) != string(after) || len(a.sessions) != 1 {
		t.Fatal("Rejected recovery changed credentials")
	}
}

func TestLocalPasswordRecoveryFailureKeepsAccess(t *testing.T) {
	a, cookie := passwordApp(t)
	old := a.s
	a.busy = true
	if w := recoveryRequest(a, "POST"); w.Code != 409 {
		t.Fatal(w.Code)
	}
	a.busy = false
	a.demo = true
	if w := recoveryRequest(a, "POST"); w.Code != 409 {
		t.Fatal(w.Code)
	}
	a.demo = false
	a.configPath = a.s.DataDir // Cannot atomically replace a nonempty directory.
	w := recoveryRequest(a, "POST")
	if w.Code != 500 || strings.Contains(w.Body.String(), `"password":`) {
		t.Fatal("Write failure returned a new password")
	}
	r := httptest.NewRequest("GET", "/api/state", nil)
	r.AddCookie(cookie)
	if !a.authorized(r) || !reflect.DeepEqual(a.s, old) {
		t.Fatal("Failed recovery revoked current access")
	}
}

func passwordApp(t *testing.T) (*App, *http.Cookie) {
	t.Helper()
	a := testApp()
	a.s.DataDir = t.TempDir()
	a.s.RouterPassword = "private-router-secret"
	a.configPath = filepath.Join(a.s.DataDir, "settings.json")
	if e := writeJSON(a.configPath, a.s); e != nil {
		t.Fatal(e)
	}
	w := request(a, "POST", "/api/login", `{"password":"testing-panel-password"}`, "router.test", "http://router.test", nil)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	return a, w.Result().Cookies()[0]
}

func passwordRequest(a *App, password, confirmation string, cookie *http.Cookie) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"password": password, "confirmation": confirmation})
	return request(a, "POST", "/api/password", string(body), "router.test", "http://router.test", cookie)
}

func TestPasswordChangePersistsAndRevokesSessionsWithoutOldPassword(t *testing.T) {
	a, cookie := passwordApp(t)
	old := a.s
	state := a.state
	w := request(a, "POST", "/api/login", `{"password":"testing-panel-password"}`, "router.test", "http://router.test", nil)
	other := w.Result().Cookies()[0]
	password := "new-private-panel-password"
	w = passwordRequest(a, password, password, cookie)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	newCookie := w.Result().Cookies()[0]
	if newCookie.Value == cookie.Value || !newCookie.HttpOnly || newCookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("Session was not rotated safely")
	}
	for _, c := range []*http.Cookie{cookie, other} {
		r := httptest.NewRequest("GET", "/api/state", nil)
		r.AddCookie(c)
		if a.authorized(r) {
			t.Fatal("Previous session still valid")
		}
	}
	r := httptest.NewRequest("GET", "/api/state", nil)
	r.AddCookie(newCookie)
	if !a.authorized(r) {
		t.Fatal("Current browser lost its session")
	}
	var saved Settings
	if e := readJSON(a.configPath, &saved); e != nil {
		t.Fatal(e)
	}
	if saved.PasswordHash == old.PasswordHash || saved.PasswordSalt == old.PasswordSalt {
		t.Fatal("Credential unchanged")
	}
	unchanged := saved
	unchanged.PasswordHash = old.PasswordHash
	unchanged.PasswordSalt = old.PasswordSalt
	if !reflect.DeepEqual(unchanged, old) || !reflect.DeepEqual(a.state, state) {
		t.Fatal("Unrelated settings changed")
	}
	content, _ := os.ReadFile(a.configPath)
	if strings.Contains(string(content), password) || strings.Contains(w.Body.String(), password) || strings.Contains(w.Body.String(), a.s.RouterPassword) {
		t.Fatal("Credential leak")
	}
	if request(a, "POST", "/api/login", `{"password":"testing-panel-password"}`, "router.test", "http://router.test", nil).Code != 401 {
		t.Fatal("Old password still accepted")
	}
	fresh := testApp()
	fresh.s = saved
	body, _ := json.Marshal(map[string]string{"password": password})
	if request(fresh, "POST", "/api/login", string(body), "router.test", "http://router.test", nil).Code != 200 {
		t.Fatal("New password not accepted after reload")
	}
}

func TestPasswordChangeRequiresSessionAndSameOrigin(t *testing.T) {
	a, cookie := passwordApp(t)
	body := `{"password":"new-panel-password-123","confirmation":"new-panel-password-123"}`
	for _, c := range []struct {
		method, origin string
		cookie         *http.Cookie
		want           int
	}{
		{"POST", "http://router.test", nil, 401}, {"POST", "http://evil.test", cookie, 403}, {"GET", "http://router.test", cookie, 405},
	} {
		if w := request(a, c.method, "/api/password", body, "router.test", c.origin, c.cookie); w.Code != c.want {
			t.Fatalf("%+v: %d", c, w.Code)
		}
	}
}

func TestPasswordValidationDoesNotChangeCredentials(t *testing.T) {
	a, cookie := passwordApp(t)
	old := a.s.PasswordHash
	for _, value := range []string{"short", strings.Repeat(" ", 16), strings.Repeat("x", 257), "sixteen-characters\n"} {
		if w := passwordRequest(a, value, value, cookie); w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	if w := passwordRequest(a, "valid-panel-password", "different-password", cookie); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if a.s.PasswordHash != old {
		t.Fatal("Rejected input changed hash")
	}
	if e := validatePassword(strings.Repeat("\u00e9", 16)); e != nil {
		t.Fatal(e)
	}
}

func TestPasswordWriteFailureAndBusyKeepCurrentAccess(t *testing.T) {
	a, cookie := passwordApp(t)
	old := a.s
	a.busy = true
	if w := passwordRequest(a, "valid-panel-password", "valid-panel-password", cookie); w.Code != 409 {
		t.Fatal(w.Code)
	}
	a.busy = false
	a.configPath = filepath.Join(a.s.DataDir, "blocked")
	if e := os.Mkdir(a.configPath, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(a.configPath, "keep"), []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	if w := passwordRequest(a, "valid-panel-password", "valid-panel-password", cookie); w.Code != 500 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("GET", "/api/state", nil)
	r.AddCookie(cookie)
	if !a.authorized(r) || !reflect.DeepEqual(a.s, old) {
		t.Fatal("Failed write lost original access")
	}
}

func TestConcurrentPasswordChangeUsesSessionOnce(t *testing.T) {
	a, cookie := passwordApp(t)
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- passwordRequest(a, "valid-panel-password", "valid-panel-password", cookie).Code
		}()
	}
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for code := range codes {
		got[code]++
	}
	if got[200] != 1 || got[401] != 1 {
		t.Fatal(got)
	}
}
