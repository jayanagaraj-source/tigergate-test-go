package src

// SCA fixtures: third-party modules pinned to versions with published CVEs,
// and actually called so reachability-based scanners (govulncheck-style)
// report them too. See SECURITY_FIXTURES.md for the CVE list.

import (
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/html"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"
)

// VULN: JWT parsed without signature verification — CWE-347
func ParseJWTUnverified(tokenString string) (jwt.MapClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	return token.Claims.(jwt.MapClaims), nil
}

// VULN: JWT key func ignores signing method (alg confusion) + hard-coded secret — CWE-347, CWE-798
// Library itself: dgrijalva/jwt-go v3.2.0 — CVE-2020-26160 (aud claim bypass)
func ParseJWTNoAlgCheck(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(JWTSigningSecret), nil
	})
}

// VULN: websocket upgrader accepts any Origin (CSWSH) — CWE-346
// Library itself: gorilla/websocket v1.4.0 — CVE-2020-27813 (integer overflow DoS)
var Upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func WebsocketEcho(w http.ResponseWriter, r *http.Request) {
	conn, err := Upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(mt, msg); err != nil {
			return
		}
	}
}

// Library: gin-gonic/gin v1.7.0 — CVE-2020-28483 (X-Forwarded-For trusted by default)
func NewRouter() *gin.Engine {
	r := gin.Default()
	r.GET("/ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})
	r.GET("/greet", func(c *gin.Context) {
		// VULN: reflected XSS through gin — CWE-79
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, "<p>Hi "+c.Query("name")+"</p>")
	})
	return r
}

// Library: gopkg.in/yaml.v3 v3.0.0 — CVE-2022-28948 (panic on malformed input)
func ParseYAML(data []byte) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	err := yaml.Unmarshal(data, &out)
	return out, err
}

// Library: golang.org/x/text v0.3.7 — CVE-2022-32149 (ParseAcceptLanguage DoS)
func ParseAcceptLanguage(header string) ([]language.Tag, error) {
	tags, _, err := language.ParseAcceptLanguage(header)
	return tags, err
}

// Library: golang.org/x/crypto — CVE-2020-9283 (ssh signature panic), CVE-2022-27191
func ParseSSHPublicKey(raw []byte) (ssh.PublicKey, error) {
	return ssh.ParsePublicKey(raw)
}

// VULN: SSH host key verification disabled — CWE-322 — gosec G106
func InsecureSSHConfig(user, password string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

// Library: golang.org/x/net (2022-07) — CVE-2022-41717, CVE-2022-41723, CVE-2023-3978, CVE-2023-39325
func ParseHTMLFragment(src string) (*html.Node, error) {
	return html.Parse(strings.NewReader(src))
}
