package src

// Web-layer fixtures: XSS, open redirect, SSRF, CORS, cookies, DoS, pprof.

import (
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" // VULN: profiling endpoint exposed on default mux — CWE-200 — gosec G108
	"time"
)

// VULN: reflected XSS, raw user input written to response — CWE-79
func ReflectedXSS(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

// VULN: XSS via html/template escape bypass with template.HTML — CWE-79 — gosec G203
func TemplateHTMLXSS(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("x").Parse("<div>{{.}}</div>"))
	_ = t.Execute(w, template.HTML(r.FormValue("content")))
}

// SAFE: html/template auto-escapes. Must NOT be flagged.
func TemplateSafe(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.New("x").Parse("<div>{{.}}</div>"))
	_ = t.Execute(w, r.FormValue("content"))
}

// VULN: open redirect — CWE-601
func OpenRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

// VULN: server-side request forgery — CWE-918 — gosec G107
func SSRF(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(w, resp.Body)
}

// VULN: wildcard CORS with credentials — CWE-942
func PermissiveCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "*")
}

// VULN: origin reflection CORS — CWE-942
func ReflectedOriginCORS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

// VULN: session cookie without Secure/HttpOnly/SameSite — CWE-614, CWE-1004
func InsecureCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		Secure:   false,
		HttpOnly: false,
	})
}

// VULN: unbounded request body read (memory exhaustion) — CWE-400
func UnboundedBodyRead(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, _ = w.Write(body)
}

// VULN: bind to all network interfaces — CWE-200 — gosec G102
func BindAllInterfaces() (net.Listener, error) {
	return net.Listen("tcp", "0.0.0.0:8080")
}

// VULN: http.ListenAndServe with no timeouts (slowloris) — CWE-400 — gosec G114
func ServeNoTimeouts() error {
	return http.ListenAndServe(":8080", nil)
}

// VULN: http.Server missing ReadHeaderTimeout — CWE-400 — gosec G112
func ServeMissingReadHeaderTimeout() error {
	srv := &http.Server{
		Addr:         ":8443",
		WriteTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// SAFE: fully configured server. Must NOT be flagged.
func ServeWithTimeouts() error {
	srv := &http.Server{
		Addr:              ":8443",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return srv.ListenAndServe()
}

// VULN: stack/internal error details leaked to client — CWE-209
func DebugErrorLeak(w http.ResponseWriter, err error) {
	http.Error(w, fmt.Sprintf("internal error: %+v", err), http.StatusInternalServerError)
}

// VULN: hard-coded Basic auth credentials sent in header — CWE-798
func CallWithBasicAuth(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic YWRtaW46cGFzc3dvcmQxMjM=") // admin:password123
	return client.Do(req)
}
