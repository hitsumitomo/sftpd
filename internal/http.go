package internal

import (
	"bytes"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"path/filepath"
	"sftp/pkg/https"
	"sftp/pkg/unique"
	"strings"
)

//go:embed web/index.html
var indexHtml []byte

//go:embed web/styles.css
var stylesCss []byte

//go:embed web/index.js
var indexJs []byte

//go:embed web/tpl/login.html
var tplLoginHtml []byte

//go:embed web/tpl/app.html
var tplAppHtml []byte

// serveHTTP configures and launches HTTP server for administrative interface.
func (s *SFTPD) serveHTTP() error {
	addr, err := s.secure.Decrypt(s.config.HTTP.Addr)
	if (err != nil) {
		return err
	}
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid HTTP address: %s", addr)
	}

	if parts[0] == "" {
		parts[0] = "secured.site"
	}

	tlsCert, err := https.GenerateECDSACert(parts[0])
	if err != nil {
		return err
	}

	mux := http.NewServeMux()

	mux.HandleFunc(s.config.HTTP.url,             s.handleWeb)
	mux.HandleFunc(s.config.HTTP.url + "/",       s.handleWeb)
	mux.HandleFunc(s.config.HTTP.url + "/login",  s.handleLogin)
	mux.HandleFunc(s.config.HTTP.url + "/logout", s.handleLogout)
	mux.HandleFunc(s.config.HTTP.url + "/config", s.authWrapper(s.handleConfig))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
			MinVersion:   tls.VersionTLS13,
		},
		ErrorLog: stdlog.New(io.Discard, "", 0), // suppress all http.Server logs
	}
	return server.ListenAndServeTLS("", "")
}

// isValidToken checks if the provided token is valid
func (s *SFTPD) isValidToken(token string) bool {
	if token == "" {
		return false
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.config.HTTP.token == token {
		return true
	}
	return false
}

// getTokenFromCookie extracts token from request cookie
func getTokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("token")
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return ""
}

// getClientIP extracts the client's IP address from the HTTP request
func getClientIP(r *http.Request) net.IP {
	ip := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	if ip == nil {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = net.ParseIP(strings.TrimSpace(strings.Split(forwarded, ",")[0]))
		}
	}
	return ip
}

// isIPAllowed checks if the given IP is allowed based on whitelist/blacklist
func (s *SFTPD) isIPAllowed(ip net.IP) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, n := range s.config.HTTP.Filter.blacklist {
		if n.Contains(ip) {
			return false
		}
	}
	if len(s.config.HTTP.Filter.whitelist) == 0 {
		return true
	}
	for _, n := range s.config.HTTP.Filter.whitelist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// authWrapper checks request authorization using cookie token and IP filters
func (s *SFTPD) authWrapper(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		if clientIP == nil || !s.isIPAllowed(clientIP) {
			http.Error(w, "Forbidden: IP not allowed", http.StatusForbidden)
			return
		}

		token := getTokenFromCookie(r)
		if token == "" {
			http.Error(w, "Unauthorized: no token", http.StatusUnauthorized)
			return
		}

		if !s.isValidToken(token) {
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		// refresh token expiration
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    token,
			Path:     s.config.HTTP.url,
			HttpOnly: true,
			Secure:   true,
			MaxAge:   3600,
			SameSite: http.SameSiteLaxMode,
		})
		next(w, r)
	}
}

// handleConfig processes configuration related requests
func (s *SFTPD) handleConfig(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        defer r.Body.Close()

        // Preserve current token before config update
        currentToken := s.config.HTTP.token

        var newConfig Config
        if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
            log.Error("Config update: invalid JSON: %v", err)
            http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
            return
        }

        // log.Dump(newConfig)

        var buf bytes.Buffer
        enc := json.NewEncoder(&buf)

        if err := enc.Encode(newConfig); err != nil {
            log.Error("Config update: failed to encode config: %v", err)
            http.Error(w, "Failed to encode config: "+err.Error(), http.StatusBadRequest)
            return
        }

        if err := s.LoadConfig(&buf); err != nil {
            log.Error("Config update: failed to store config: %v", err)
            http.Error(w, "Failed to store config: "+err.Error(), http.StatusBadRequest)
        }

        // Restore the session token after config update
        s.mutex.Lock()
        s.config.HTTP.token = currentToken
        s.mutex.Unlock()

        return
    }

    w.Header().Set("Content-Type", "application/json")
    if err := s.ExportConfig(w); err != nil {
        log.Error("Config export: failed to export config: %v", err)
        w.WriteHeader(http.StatusInternalServerError)
    }
}

// handleWeb processes all web requests - both static files and the root path
func (s *SFTPD) handleWeb(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if clientIP == nil || !s.isIPAllowed(clientIP) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Check for template paths
	if strings.Contains(r.URL.Path, "/tpl/") {
		tplName := filepath.Base(r.URL.Path)
		w.Header().Set("Content-Type", "text/html")

		switch tplName {
		case "login.html":
			w.Write(tplLoginHtml)
		case "app.html":
			w.Write(tplAppHtml)
		default:
			w.WriteHeader(http.StatusForbidden)
		}
		return
	}

	if r.URL.Path == s.config.HTTP.url {
		token := getTokenFromCookie(r)
		if s.isValidToken(token) {
			// User is authenticated, serve embedded index.html
			w.Header().Set("Content-Type", "text/html")
			w.Write(indexHtml)
			return
		}

		// User is not authenticated, serve embedded login template
		w.Header().Set("Content-Type", "text/html")
		w.Write(tplLoginHtml)
		return
	}

	// Handle static files
	relPath := strings.Replace(r.URL.Path, s.config.HTTP.url, "", 1)
	cleanPath := filepath.Clean(strings.TrimPrefix(relPath, "/"))

	if strings.Contains(cleanPath, "..") {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	switch cleanPath {
	case "index.html":
		w.Header().Set("Content-Type", "text/html")
		w.Write(indexHtml)
	case "styles.css":
		w.Header().Set("Content-Type", "text/css")
		w.Write(stylesCss)
	case "index.js":
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(indexJs)
	}
	w.WriteHeader(http.StatusNotFound)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin processes user authentication
func (s *SFTPD) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if clientIP == nil || !s.isIPAllowed(clientIP) {
		log.Error("web login denied: IP not allowed (%v)", clientIP)
		// http.Error(w, "Forbidden: IP not allowed", http.StatusForbidden)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Method != http.MethodPost {
		log.Error("web login denied: method not allowed (%s)", r.Method)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Error("web login denied: invalid JSON (%v)", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Validate admin credentials from HTTP section
	// use already‐decrypted runtime credentials
	username := s.config.HTTP.username
	password := s.config.HTTP.password

	if req.Username != username || req.Password != password {
		log.Error("web login denied: invalid credentials (user=%q, ip=%v)", req.Username, clientIP)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate token and set cookie
	token := unique.Token()
	s.mutex.Lock()
	s.config.HTTP.token = token
	s.mutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     s.config.HTTP.url,
		HttpOnly: true,
		Secure:   true,
		MaxAge:   3600,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *SFTPD) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Invalidate the token in the server state
	s.mutex.Lock()
	s.config.HTTP.token = ""
	s.mutex.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     s.config.HTTP.url,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}