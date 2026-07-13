//go:build darwin

package certstore

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const testKeychainPass = "test-caddy-certstore"

var (
	testKeychainMu       sync.Mutex
	testKeychainPath     string
	testKeychainDir      string
	testKeychainImported bool
)

func TestMain(m *testing.M) {
	code := m.Run()

	if testKeychainPath != "" {
		_ = exec.Command("security", "delete-keychain", testKeychainPath).Run()
	}
	if testKeychainDir != "" {
		_ = os.RemoveAll(testKeychainDir)
	}

	os.Exit(code)
}

// importTestCertificate imports the test certificate into a temporary keychain.
// Full tests touch the macOS keychain search list, but they restore the original
// list and delete the disposable keychain during test cleanup.
func importTestCertificate(t *testing.T) {
	t.Helper()

	p12Path, err := filepath.Abs(testCertP12)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		t.Fatalf("Test certificate not found at %s. Run 'make test-cert' to generate it.", p12Path)
	}

	originalSearchList := listKeychains(t)
	originalDefaultKeychain := defaultKeychain(t)
	keychainPath := ensureTestKeychain(t, p12Path)

	t.Cleanup(func() {
		restoreDefaultKeychain(t, originalDefaultKeychain)
		restoreKeychainSearchList(t, originalSearchList)
	})

	runSecurity(t, "unlock-keychain", "-p", testKeychainPass, keychainPath)
	setKeychainSearchList(t, append([]string{keychainPath}, originalSearchList...))
	setDefaultKeychain(t, keychainPath)

	t.Logf("Successfully imported certificate to temporary keychain: %s", testCertCN)
}

func ensureTestKeychain(t *testing.T, p12Path string) string {
	t.Helper()

	testKeychainMu.Lock()
	defer testKeychainMu.Unlock()

	if testKeychainPath == "" {
		dir, err := os.MkdirTemp("", "caddy-certstore-test-*")
		if err != nil {
			t.Fatalf("Failed to create temporary keychain directory: %v", err)
		}
		testKeychainDir = dir
		testKeychainPath = filepath.Join(dir, "caddy-certstore-test.keychain-db")
		runSecurity(t, "create-keychain", "-p", testKeychainPass, testKeychainPath)
		runSecurity(t, "unlock-keychain", "-p", testKeychainPass, testKeychainPath)
		runSecurity(t, "set-keychain-settings", "-lut", "21600", testKeychainPath)
	}

	if !testKeychainImported {
		// -A is scoped to this disposable keychain so the Go test process can use the
		// private key without prompting on developer machines.
		runSecurity(
			t,
			"import", p12Path,
			"-k", testKeychainPath,
			"-P", testCertPass,
			"-A",
		)
		testKeychainImported = true
	}

	return testKeychainPath
}

func listKeychains(t *testing.T) []string {
	t.Helper()

	output, err := exec.Command("security", "list-keychains", "-d", "user").CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to list keychains: %v\nOutput: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	keychains := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		keychains = append(keychains, parseKeychainLine(line))
	}
	return keychains
}

func parseKeychainLine(line string) string {
	if unquoted, err := strconv.Unquote(line); err == nil {
		return unquoted
	}
	return line
}

func defaultKeychain(t *testing.T) string {
	t.Helper()

	output, err := exec.Command("security", "default-keychain", "-d", "user").CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to get default keychain: %v\nOutput: %s", err, output)
	}
	return parseKeychainLine(strings.TrimSpace(string(output)))
}

func setDefaultKeychain(t *testing.T, keychain string) {
	t.Helper()

	runSecurity(t, "default-keychain", "-d", "user", "-s", keychain)
}

func restoreDefaultKeychain(t *testing.T, keychain string) {
	t.Helper()

	if keychain == "" {
		return
	}
	cmd := exec.Command("security", "default-keychain", "-d", "user", "-s", keychain)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("Failed to restore default keychain: %v\nOutput: %s", err, output)
	}
}

func setKeychainSearchList(t *testing.T, keychains []string) {
	t.Helper()

	args := append([]string{"list-keychains", "-d", "user", "-s"}, keychains...)
	runSecurity(t, args...)
}

func restoreKeychainSearchList(t *testing.T, keychains []string) {
	t.Helper()

	args := append([]string{"list-keychains", "-d", "user", "-s"}, keychains...)
	cmd := exec.Command("security", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("Failed to restore keychain search list: %v\nOutput: %s", err, output)
	}
}

func runSecurity(t *testing.T, args ...string) {
	t.Helper()

	cmd := exec.Command("security", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("security %s failed: %v\nOutput: %s", strings.Join(args, " "), err, output)
	}
}

// removeTestCertificate is kept for cross-platform test compatibility.
// macOS cleanup is handled by importTestCertificate's t.Cleanup callback.
func removeTestCertificate(t *testing.T) {
	t.Helper()
}
