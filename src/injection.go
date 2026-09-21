package src

// Injection fixtures: SQL, OS command, template, and log injection.
// Every function here is intentionally vulnerable unless marked SAFE.

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"text/template"
)

// VULN: SQL injection via fmt.Sprintf — CWE-89 — gosec G201
func SQLInjectionSprintf(db *sql.DB, name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT id, email FROM users WHERE name = '%s'", name)
	return db.Query(query)
}

// VULN: SQL injection via string concatenation — CWE-89 — gosec G202
func SQLInjectionConcat(db *sql.DB, id string) *sql.Row {
	return db.QueryRow("SELECT * FROM orders WHERE id = " + id)
}

// VULN: SQL injection from HTTP input straight into Exec — CWE-89 — gosec G202
func SQLInjectionHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		_, err := db.Exec("DELETE FROM users WHERE email = '" + email + "'")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// SAFE: parameterised query. A correct scanner must NOT flag this.
func SQLSafeParameterised(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT id, email FROM users WHERE name = ?", name)
}

// VULN: OS command injection through shell — CWE-78 — gosec G204
func CommandInjectionShell(host string) ([]byte, error) {
	return exec.Command("sh", "-c", "ping -c 1 "+host).CombinedOutput()
}

// VULN: OS command injection, attacker-controlled binary — CWE-78 — gosec G204
func CommandInjectionBinary(bin string, args ...string) error {
	return exec.Command(bin, args...).Run()
}

// VULN: command injection sourced from HTTP request — CWE-78 — gosec G204
func CommandInjectionHandler(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("nslookup", r.FormValue("domain")).Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(out)
}

// SAFE: fixed binary and fixed args. Must NOT be flagged.
func CommandSafeFixed() ([]byte, error) {
	return exec.Command("uptime").Output()
}

// VULN: server-side template injection (user input parsed as template) — CWE-1336
func TemplateInjection(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("page").Parse(r.URL.Query().Get("tpl"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_ = tmpl.Execute(w, map[string]string{"user": "alice"})
}

// VULN: log injection + sensitive data written to logs — CWE-117, CWE-532
func LogInjection(username, password string) {
	log.Printf("login attempt user=%s password=%s", username, password)
}
