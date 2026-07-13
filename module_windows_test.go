//go:build windows

package certstore

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// importTestCertificate imports the test certificate from testdata into user certificate store.
// Full tests touch Cert:\CurrentUser\My and cleanup removes only the exact test PFX thumbprint.
func importTestCertificate(t *testing.T) {
	t.Helper()

	pfxPath, err := filepath.Abs(testCertP12)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	if _, err := os.Stat(pfxPath); os.IsNotExist(err) {
		t.Fatalf("Test certificate not found at %s", pfxPath)
	}

	psScript := `
		$password = ConvertTo-SecureString -String "` + testCertPass + `" -AsPlainText -Force
		try {
			$cert = Import-PfxCertificate -FilePath "` + pfxPath + `" -CertStoreLocation Cert:\CurrentUser\My -Password $password -Exportable
			Write-Output "SUCCESS: Imported certificate with thumbprint $($cert.Thumbprint)"
		} catch {
			if ($_.Exception.Message -like "*already exists*") {
				Write-Output "INFO: Certificate already exists"
				exit 0
			}
			Write-Error $_.Exception.Message
			exit 1
		}
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to import certificate: %v\nOutput: %s", err, output)
	}

	t.Logf("Certificate import result: %s", output)
}

// removeTestCertificate removes only the exact test certificate from user certificate store.
func removeTestCertificate(t *testing.T) {
	t.Helper()

	pfxPath, err := filepath.Abs(testCertP12)
	if err != nil {
		t.Logf("Failed to get absolute test certificate path during cleanup: %v", err)
		return
	}

	psScript := `
		$password = ConvertTo-SecureString -String "` + testCertPass + `" -AsPlainText -Force
		$expected = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("` + pfxPath + `", $password)
		$cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $expected.Thumbprint }
		if ($cert) {
			Remove-Item -Path "Cert:\CurrentUser\My\$($expected.Thumbprint)" -Force
			Write-Output "Removed test certificate: $($expected.Thumbprint)"
		}
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	_ = cmd.Run()
}
