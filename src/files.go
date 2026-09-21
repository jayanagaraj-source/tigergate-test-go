package src

// Filesystem fixtures: path traversal, zip slip, decompression bomb,
// insecure permissions, predictable temp files, TOCTOU.

import (
	"archive/zip"
	"compress/gzip"
	"io"
	"io/ioutil" // deprecated since Go 1.16
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// VULN: path traversal from HTTP input — CWE-22 — gosec G304
func PathTraversalHandler(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("/var/app/uploads/" + r.URL.Query().Get("file"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_, _ = w.Write(data)
}

// VULN: filepath.Join does not neutralise ".." — CWE-22 — gosec G304
func ReadUserFile(base, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(base, name))
}

// VULN: os.Open with tainted path — CWE-22 — gosec G304
func OpenUserFile(path string) (*os.File, error) {
	return os.Open(path)
}

// SAFE: path is cleaned and confined to base. Must NOT be flagged.
func ReadUserFileSafe(base, name string) ([]byte, error) {
	clean := filepath.Join(base, filepath.Clean("/"+name))
	if !strings.HasPrefix(clean, filepath.Clean(base)+string(os.PathSeparator)) {
		return nil, os.ErrPermission
	}
	return os.ReadFile(clean)
}

// VULN: zip slip — CWE-22 — gosec G305; also G110, G301, G302, G110
func ExtractZip(archive, dest string) error {
	rd, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer rd.Close()
	for _, f := range rd.File {
		target := filepath.Join(dest, f.Name) // no ".." check
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0777); err != nil { // VULN: G301
				return err
			}
			continue
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666) // VULN: G302
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			out.Close()
			return err
		}
		_, err = io.Copy(out, rc) // VULN: unbounded copy — G110
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// VULN: gzip decompression bomb — CWE-409 — gosec G110
func DecompressUnbounded(r io.Reader, w io.Writer) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	_, err = io.Copy(w, gz)
	return err
}

// VULN: world-writable directory / file / chmod — CWE-276, CWE-732 — gosec G301, G306, G302
func InsecurePermissions(dir string) error {
	if err := os.MkdirAll(dir, 0777); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("debug: true\n"), 0666); err != nil {
		return err
	}
	return os.Chmod(dir, 0777)
}

// VULN: predictable path in shared temp dir — CWE-377 — gosec G303
func PredictableTempFile(data []byte) error {
	return ioutil.WriteFile("/tmp/app-cache.dat", data, 0644)
}

// VULN: time-of-check / time-of-use — CWE-367
func ReadIfExists(path string) ([]byte, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// VULN: file handle leaked on early return — CWE-772
func LeakHandle(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	st, err := f.Stat()
	if err != nil {
		return 0, err // f never closed
	}
	f.Close()
	return st.Size(), nil
}
