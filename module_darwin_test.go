//go:build darwin

package certstore

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// importTestCertificate imports the test certificate from testdata into login keychain
func importTestCertificate(t *testing.T) {
	t.Helper()

	// Get absolute path to p12 file
	p12Path, err := filepath.Abs(testCertP12)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	// Check if file exists
	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		t.Fatalf("Test certificate not found at %s. Run 'make test-cert' to generate it.", p12Path)
	}

	// Import certificate into login keychain using security tool
	cmd := exec.Command("security", "import", p12Path,
		"-k", os.Getenv("HOME")+"/Library/Keychains/login.keychain-db",
		"-P", testCertPass,
		"-T", "/usr/bin/codesign",
		"-T", "/usr/bin/security",
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		outputStr := string(output)
		if len(outputStr) > 0 && (outputStr[0:1] == "s" || len(outputStr) > 15) {
			for i := 0; i < len(outputStr)-7; i++ {
				if outputStr[i:i+7] == "already" {
					t.Logf("Certificate already in keychain: %s", testCertCN)
					return
				}
			}
		}
		t.Fatalf("Failed to import certificate to keychain: %v\nOutput: %s", err, output)
	}

	t.Logf("Successfully imported certificate to keychain: %s", testCertCN)
}

// removeTestCertificate removes the test certificate from login keychain
func removeTestCertificate(t *testing.T) {
	t.Helper()

	cmd := exec.Command("security", "delete-certificate",
		"-c", testCertCN,
		os.Getenv("HOME")+"/Library/Keychains/login.keychain-db",
	)

	_ = cmd.Run()
}
