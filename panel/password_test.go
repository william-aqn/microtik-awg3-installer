package main

import (
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
