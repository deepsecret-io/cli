// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
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

// callbackTemplate renders the browser landing page that extracts the JWT
// and client_state from the URL fragment and POSTs both back to /receive.
//
// The page deliberately does NOT know the CLI's state. The API echoes the
// state in the redirect fragment of the genuine login only, so a page that
// navigates the browser here with a planted #token= cannot supply it, and
// /receive rejects the token. Any local process can still fetch this page,
// but it learns nothing secret from it.
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
  var msg=document.getElementById('msg');
  function setMsg(text,color){
    while(msg.firstChild){msg.removeChild(msg.firstChild);}
    var p=document.createElement('p');
    if(color){p.style.color=color;}
    p.textContent=text;
    msg.appendChild(p);
  }
  var f=new URLSearchParams(window.location.hash.slice(1));
  history.replaceState(null,'',window.location.pathname);
  var t=f.get('token'),s=f.get('client_state');
  if(!t||!s){setMsg('Authentication failed.','#ef4444');return;}
  fetch('/receive',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t,state:s})})
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
is stored locally for CLI usage. It renews while you use the CLI, for up
to 7 days from sign-in; after an hour unused, sign in again. API keys are
still supported for CI/CD.

Examples:
  secret login          # authenticate via browser
  secret login --check  # show current auth status`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if check {
				return showAuthStatus()
			}
			return browserLogin()
		},
	}

	cmd.Flags().BoolVar(&check, "check", false, "Show the current authentication status instead of signing in")
	setGroup(cmd.Flags(), groupOptions, "check")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke and remove the stored login token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tf, err := loadTokenFile()
			if err != nil || tf.Token == "" {
				return fmt.Errorf("no active session")
			}
			// Revoke server-side first so a copy of the token stops
			// working, then remove it locally whatever the outcome.
			revokeErr := revokeToken(apiBaseURL, tf.Token)
			if err := removeToken(); err != nil {
				return fmt.Errorf("remove token: %w", err)
			}
			if revokeErr != nil {
				printDim("Token removed locally, but the server could not revoke it: " + revokeErr.Error())
				printDim("It stays valid until it expires (at most 1 hour).")
				return nil
			}
			printSuccess("Logged out. Token revoked and removed.")
			return nil
		},
	}
}

// revokeToken asks the API to blacklist the bearer token.
func revokeToken(apiBase, token string) error {
	c, err := NewClient(apiBase, "bearer:"+token)
	if err != nil {
		return err
	}
	return c.Logout()
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
				printKeyValue("Expires", "EXPIRED (run: secret login)")
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
		w.Header().Set("Referrer-Policy", "no-referrer")
		_ = callbackTemplate.Execute(w, nil)
	})

	// Receive the token from the callback page JS
	mux.HandleFunc("/receive", receiveToken(state, tokenCh))

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
	// stopServer shuts the callback server down, giving open requests up to
	// five seconds.
	stopServer := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx) // a loopback server for one callback; the login's own result is returned, and the process exits soon after.
	}

	// Fetch the Google auth URL from the API (don't send browser to API
	// directly). client_state is echoed back only in the genuine redirect.
	ssoQuery := url.Values{"return_url": {callbackURL}, "client_state": {state}}
	ssoReqURL := fmt.Sprintf("%s/api/v1/auth/sso/google?%s", apiBase, ssoQuery.Encode())
	httpClient := &http.Client{Timeout: 10 * time.Second}
	httpResp, err := httpClient.Get(ssoReqURL)
	if err != nil {
		stopServer()
		return fmt.Errorf("failed to reach API: %w", err)
	}
	defer httpResp.Body.Close()
	authURL, err := readAuthURL(httpResp.Body)
	if err != nil {
		stopServer()
		return fmt.Errorf("failed to get auth URL from API (is the server running at %s?): %w", apiBase, err)
	}

	// Validate the server-supplied URL before handing it to the OS browser
	// launcher; reject javascript:/file:/smb:/etc. schemes outright.
	safeURL, err := safeBrowserURL(authURL)
	if err != nil {
		stopServer()
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
		stopServer()
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
		stopServer()
		return fmt.Errorf("local server error: %w", err)

	case <-ctx.Done():
		stopServer()
		return fmt.Errorf("login timed out (2 minutes). Try again with: secret login")
	}
}

// Bounds on the login flow's bodies, each holding one URL or one session
// token of a few KB, so neither the API nor a local process can make the
// CLI read without end. A body over its bound fails.
const (
	// maxAuthURLResponse bounds the API's answer naming the auth URL.
	maxAuthURLResponse = 64 << 10
	// maxTokenPost bounds what the callback page posts to /receive.
	maxTokenPost = 64 << 10
)

// readAuthURL reads the API's answer to the SSO request and returns the
// auth URL in it.
func readAuthURL(r io.Reader) (string, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxAuthURLResponse+1))
	if err != nil {
		return "", err
	}
	if len(body) > maxAuthURLResponse {
		return "", fmt.Errorf("the answer is over %d bytes", maxAuthURLResponse)
	}
	var resp struct {
		Data struct {
			AuthURL string `json:"auth_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("decode the answer: %w", err)
	}
	if resp.Data.AuthURL == "" {
		return "", fmt.Errorf("the answer has no auth URL")
	}
	return resp.Data.AuthURL, nil
}

// receiveToken handles the callback page's POST of the session token and
// the login state, and passes on a token whose state matches.
func receiveToken(state string, tokenCh chan<- string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// reply answers the callback page. A failed write means the page
		// has gone, and there is nothing left to tell it.
		reply := func(body string) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
		}
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Token string `json:"token"`
			State string `json:"state"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxTokenPost)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			reply(`{"ok":false,"error":"invalid request"}`)
			return
		}

		// The state only reaches this listener through the fragment of the
		// genuine login redirect. A mismatch means the token was planted.
		if subtle.ConstantTimeCompare([]byte(body.State), []byte(state)) != 1 {
			reply(`{"ok":false,"error":"state mismatch"}`)
			return
		}

		// Validate token is a real JWT (3 parts, can parse claims)
		if err := validateJWTFormat(body.Token); err != nil {
			reply(`{"ok":false,"error":"invalid token format"}`)
			return
		}

		reply(`{"ok":true}`)

		tokenCh <- body.Token
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
// `javascript:`, `file:`, `smb:` and others, so any server-supplied URL must be
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
		cmd = exec.Command("open", clean) // #nosec G204 -- a fixed program; clean passed safeBrowserURL (https, or http on loopback) and no shell is involved.
	case "linux":
		cmd = exec.Command("xdg-open", clean) // #nosec G204 -- a fixed program; clean passed safeBrowserURL (https, or http on loopback) and no shell is involved.
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", clean) // #nosec G204 -- a fixed program; clean passed safeBrowserURL (https, or http on loopback) and no shell is involved.
	}
	if cmd != nil {
		_ = cmd.Start()
	}
	return nil
}
