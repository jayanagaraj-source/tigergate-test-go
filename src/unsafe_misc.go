package src

// Miscellaneous fixtures: unsafe, unhandled errors, integer narrowing,
// out-of-bounds access, data races, hard-coded credentials in config.

import (
	"os"
	"strconv"
	"sync"
	"unsafe"
)

// VULN: unsafe pointer arithmetic — CWE-119 — gosec G103
func UnsafePointerRead(b []byte) byte {
	p := unsafe.Pointer(&b[0])
	return *(*byte)(unsafe.Pointer(uintptr(p) + 8))
}

// VULN: unhandled errors — CWE-252 — gosec G104
func UnhandledErrors(path string) {
	f, _ := os.Create(path)
	f.WriteString("data")
	f.Close()
	os.Remove(path)
}

// VULN: integer overflow via narrowing conversion — CWE-190 — gosec G115
func NarrowingConversion(s string) int32 {
	n, _ := strconv.Atoi(s)
	return int32(n)
}

// VULN: unsigned narrowing used as a length — CWE-190 — gosec G115
func LengthFromInput(n int) []byte {
	return make([]byte, uint8(n))
}

// VULN: slice index out of range (runtime panic) — CWE-125 — gosec G602
func SliceOutOfBounds() int {
	n := 3
	s := make([]int, n)
	return s[5]
}

// VULN: nil map write (runtime panic) — CWE-476
func NilMapWrite(k, v string) {
	var m map[string]string
	m[k] = v
}

// VULN: unsynchronised concurrent write (data race) — CWE-362
var hitCounter int

func RaceyIncrement() {
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hitCounter++
		}()
	}
	wg.Wait()
}

// VULN: hard-coded credentials in config — CWE-798 — gosec G101
const (
	dbUser     = "app"
	dbPassword = "Sup3rS3cret!"
)

var DBConfig = struct {
	Host, User, Password string
}{
	Host:     "db.internal:5432",
	User:     dbUser,
	Password: dbPassword,
}

// VULN: debug mode toggled on by default in production config — CWE-489
var Config = map[string]bool{
	"debug":              true,
	"verify_tls":         false,
	"allow_admin_bypass": true,
}
