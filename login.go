// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// callbackTemplate renders the browser landing page that extracts the JWT from
// the URL fragment and POSTs it back. Using html/template guarantees `.State`
// is JS-escaped when interpolated inside <script>.
//
// The DOM is built via document.createElement/textContent (not innerHTML), so
// even an attacker-controlled error string from /receive cannot inject markup.
var callbackTemplate = template.Must(template.New("callback").Parse(`<!DOCTYPE html>
<html><head><title>DeepSecret Login</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#050508;color:#a1a1aa}
.box{text-align:center;padding:2rem}.ok{color:#22c55e;font-size:1.5rem;margin-bottom:1rem}</style></head>
<body><div class="box" id="msg"><p id="msg-text">Authenticating...</p></div>
<script>
(function(){
  var STATE={{.State}};
  var msg=document.getElementById('msg');
  function setMsg(text,color){
    while(msg.firstChild){msg.removeChild(msg.firstChild);}
    var p=document.createElement('p');
    if(color){p.style.color=color;}
    p.textContent=text;
    msg.appendChild(p);
  }
  var h=window.location.hash;
  if(!h||h.indexOf('token=')<0){setMsg('Authentication failed.','#ef4444');return;}
  var t=h.split('token=')[1];if(!t){setMsg('No token received.','#ef4444');return;}
  fetch('/receive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t,state:STATE})})
  .then(function(r){return r.json();})
  .then(function(d){
    if(d.ok){setMsg('Authenticated. You can close this tab.','#22c55e');}
    else{setMsg(String(d.error||'Authentication failed.'),'#ef4444');}
  }).catch(function(){setMsg('Failed to complete login.','#ef4444');});
})();
</script></body></html>`))

func newLoginCmd() *cobra.Command {
	var check bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate via browser SSO",
		Long: `Open the browser to authenticate with Google SSO. A short-lived token
is stored locally for CLI usage. API keys are still supported for CI/CD.

Examples:
  secret login          # authenticate via browser
  secret login --check  # show current auth status`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if check {
				return showAuthStatus()
			}
			return browserLogin()
		},
	}

	cmd.Flags().BoolVar(&check, "check", false, "Show current authentication status")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove stored login token",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := removeToken(); err != nil {
				return fmt.Errorf("no active session")
			}
			printSuccess("Logged out. Token removed.")
			return nil
		},
	}
}

func showAuthStatus() error {
	tf, err := loadTokenFile()
	if err != nil {
		printDim("Not logged in. Run: secret login")
		if cfg, err := loadConfig(); err == nil && cfg.APIKey != "" {
			fmt.Println()
			printKeyValue("Auth", "API Key (configured)")
			printKeyValue("API URL", apiBaseURL)
		}
		return nil
	}

	printHeader("Authentication Status")
	fmt.Println()
	printKeyValue("Email", tf.Email)
	printKeyValue("Method", "SSO (browser login)")

	if tf.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, tf.ExpiresAt)
		if err == nil {
			remaining := time.Until(exp)
			if remaining > 0 {
				printKeyValue("Expires", fmt.Sprintf("%s (%s remaining)", exp.Format("15:04:05"), remaining.Round(time.Minute)))
			} else {
				printKeyValue("Expires", "EXPIRED — run: secret login")
			}
		}
	}

	// Also show API key status
	if cfg, err := loadConfig(); err == nil && cfg.APIKey != "" {
		fmt.Println()
		printKeyValue("API Key", "configured (takes priority over login token)")
	}
	fmt.Println()
	return nil
}

func browserLogin() error {
	apiBase := apiBaseURL
	logInfo("ds.login", fmt.Sprintf("starting browser SSO flow, api=%s", apiBase))

	// Generate state for CSRF protection
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		return fmt.Errorf("generate state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	// Bind a free port on loopback. Pass the listener to Serve directly so we
	// don't lose the port in a TOCTOU window between Close() and rebind.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start local server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)

	// Start local HTTP server (one-shot, 127.0.0.1 only)
	mux := http.NewServeMux()

	// The callback page: browser loads this with #token=jwt in fragment.
	// Since fragments aren't sent to the server, JS extracts it and POSTs to /receive.
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		_ = callbackTemplate.Execute(w, struct{ State string }{State: state})
	})

	// Receive the token from the callback page JS
	mux.HandleFunc("/receive", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		var body struct {
			Token string `json:"token"`
			State string `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"ok":false,"error":"invalid request"}`)
			return
		}

		// Validate state to prevent CSRF
		if body.State != state {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"ok":false,"error":"state mismatch"}`)
			return
		}

		// Validate token is a real JWT (3 parts, can parse claims)
		if err := validateJWTFormat(body.Token); err != nil {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"ok":false,"error":"invalid token format"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true}`)

		tokenCh <- body.Token
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Start server in background using the already-bound listener.
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Fetch the Google auth URL from the API (don't send browser to API directly)
	ssoReqURL := fmt.Sprintf("%s/api/v1/auth/sso/google?return_url=%s", apiBase, callbackURL)
	httpClient := &http.Client{Timeout: 10 * time.Second}
	httpResp, err := httpClient.Get(ssoReqURL)
	if err != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(shutdownCtx)
		shutdownCancel()
		return fmt.Errorf("failed to reach API: %w", err)
	}
	defer httpResp.Body.Close()
	var ssoResp struct {
		Data struct {
			AuthURL string `json:"auth_url"`
		} `json:"data"`
	}
	if err := json.NewDecoder(httpResp.Body).Decode(&ssoResp); err != nil || ssoResp.Data.AuthURL == "" {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(shutdownCtx)
		shutdownCancel()
		return fmt.Errorf("failed to get auth URL from API (is the server running at %s?)", apiBase)
	}

	authURL := ssoResp.Data.AuthURL

	// Validate the server-supplied URL before handing it to the OS browser
	// launcher; reject javascript:/file:/smb:/etc. schemes outright.
	safeURL, err := safeBrowserURL(authURL)
	if err != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(shutdownCtx)
		shutdownCancel()
		return fmt.Errorf("API returned an unsafe auth URL: %w", err)
	}

	fmt.Fprintln(os.Stderr, "ds.login: opening browser for authentication")
	fmt.Fprintln(os.Stderr, "ds.login: if the browser doesn't open, visit:")
	fmt.Fprintln(os.Stderr, "  "+safeURL)
	fmt.Fprintln(os.Stderr)

	// Open browser to Google directly (not the API server)
	_ = openBrowser(safeURL)

	// Wait for token or timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	select {
	case token := <-tokenCh:
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(shutdownCtx)
		shutdownCancel()
		logInfo("ds.login", "token received from browser callback")

		// Parse JWT to get expiry; email is fetched from the server below.
		expiresAt := extractJWTExpiry(token)
		email := fetchEmailForToken(apiBase, token)

		if err := saveToken(token, email, expiresAt); err != nil {
			return fmt.Errorf("save token: %w", err)
		}

		printSuccess("Authenticated")
		if email != "" {
			printKeyValue("Email", email)
		}
		if expiresAt != "" {
			exp, _ := time.Parse(time.RFC3339, expiresAt)
			printKeyValue("Expires", exp.Format("15:04:05"))
		}
		fmt.Println()
		return nil

	case err := <-errCh:
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(shutdownCtx)
		shutdownCancel()
		return fmt.Errorf("local server error: %w", err)

	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		server.Shutdown(shutdownCtx)
		shutdownCancel()
		return fmt.Errorf("login timed out (2 minutes). Try again with: secret login")
	}
}

// validateJWTFormat checks that the string looks like a valid JWT (3 base64url parts).
func validateJWTFormat(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a JWT")
	}
	for _, p := range parts {
		if len(p) == 0 {
			return fmt.Errorf("empty JWT segment")
		}
	}
	return nil
}

// extractJWTExpiry parses the JWT payload without verification to get the
// expiry timestamp. We trust the token came from our server via the secure SSO flow.
func extractJWTExpiry(tokenStr string) string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return ""
	}
	payload := parts[1]
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	data, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if json.Unmarshal(data, &claims) != nil {
		return ""
	}
	if claims.Exp > 0 {
		return time.Unix(int64(claims.Exp), 0).Format(time.RFC3339)
	}
	return ""
}

// fetchEmailForToken calls whoami with the given bearer token to retrieve the
// actor's email. Returns empty string on any failure so login still succeeds.
func fetchEmailForToken(apiBase, token string) string {
	c, err := NewClient(apiBase, "bearer:"+token)
	if err != nil {
		return ""
	}
	info, err := c.WhoAmI()
	if err != nil || info == nil {
		return ""
	}
	return info.Email
}

// safeBrowserURL returns the URL only if it parses, has a safe scheme
// (https, or http on a loopback host), and a non-empty host. The OS browser
// launchers (`open`, `xdg-open`, `rundll32`) will happily dispatch
// `javascript:`, `file:`, `smb:`, etc. — so any server-supplied URL must be
// validated before being passed to a shell helper.
func safeBrowserURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("malformed URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		// always allowed
	case "http":
		host := u.Hostname()
		if host != "127.0.0.1" && host != "::1" && host != "localhost" {
			return "", fmt.Errorf("plaintext http only allowed for localhost (got %q)", host)
		}
	default:
		return "", fmt.Errorf("scheme %q not allowed; expected https", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("URL has no host")
	}
	return u.String(), nil
}

func openBrowser(rawURL string) error {
	clean, err := safeBrowserURL(rawURL)
	if err != nil {
		return err
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", clean)
	case "linux":
		cmd = exec.Command("xdg-open", clean)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", clean)
	}
	if cmd != nil {
		_ = cmd.Start()
	}
	return nil
}
