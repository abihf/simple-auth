package main

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

//go:embed login.html
var loginPage []byte

var cookieName = os.Getenv("COOKIE_NAME")
var cookieSecret = os.Getenv("COOKIE_SECRET")
var authUser = os.Getenv("AUTH_USER")
var authPass = os.Getenv("AUTH_PASS")
var listenAddr = os.Getenv("LISTEN_ADDR")
var upstreamAddr = os.Getenv("UPSTREAM_ADDR")

var proxy = httputil.NewSingleHostReverseProxy(&url.URL{
	Scheme: "http",
	Host:   upstreamAddr,
})

func main() {
	err := http.ListenAndServe(listenAddr, http.HandlerFunc(handler))
	if err != nil {
		panic(err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/_simple-auth/login" {
		loginHandler(w, r)
		return
	}

	if !isLoggedin(r) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(loginPage)
		return
	}

	// forward to upstream
	proxy.ServeHTTP(w, r)
}

func isLoggedin(r *http.Request) bool {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	_, err = validateCookie([]byte(cookie.Value))
	return err == nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	redirect := r.FormValue("redirect")
	if username != authUser || password != authPass {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "invalid username or password")
		return
	}

	cookieData := newCookieData(username)
	cookieValue, err := json.Marshal(cookieData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to create cookie")
		return
	}

	cookie := &http.Cookie{
		Name:    cookieName,
		Value:   string(cookieValue),
		Expires: time.Unix(cookieData.Expire, 0),
		Path:    "/",
	}
	http.SetCookie(w, cookie)
	w.Header().Set("Location", redirect)
	w.WriteHeader(http.StatusFound)
}

type CookieData struct {
	Username string `json:"usr"`
	Expire   int64  `json:"exp"`
	Hash     []byte `json:"hash"`
}

func (c *CookieData) calculateHash() []byte {
	h := hmac.New(sha256.New, []byte(cookieSecret))
	fmt.Fprintf(h, "%s:%d", c.Username, c.Expire)
	hash := h.Sum(nil)
	return []byte(base64.URLEncoding.EncodeToString(hash))
}

func newCookieData(username string) *CookieData {
	c := &CookieData{
		Username: username,
		Expire:   time.Now().Add(time.Hour * 24 * 30).Unix(),
	}
	c.Hash = c.calculateHash()
	return c
}

func validateCookie(data []byte) (*CookieData, error) {
	c := &CookieData{}
	err := json.Unmarshal(data, c)
	if err != nil {
		return nil, err
	}
	if c.Expire < time.Now().Unix() {
		return nil, fmt.Errorf("cookie expired")
	}
	expectedHash := c.calculateHash()
	if !hmac.Equal(expectedHash, c.Hash) {
		return nil, fmt.Errorf("cookie hash mismatch")
	}
	return c, nil
}
