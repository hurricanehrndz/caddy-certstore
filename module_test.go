package certstore

import (
	"testing"
)

func TestIsRegexPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"simple FQDN", "example.com", false},
		{"FQDN with subdomain", "sub.example.com", false},
		{"asterisk wildcard", "*.example.com", true},
		{"plus quantifier", "test+", true},
		{"question mark", "test?", true},
		{"caret anchor", "^test", true},
		{"dollar anchor", "test$", true},
		{"parentheses", "(test)", true},
		{"square brackets", "[test]", true},
		{"curly braces", "{test}", true},
		{"pipe", "test|other", true},
		{"backslash", "test\\d", true},
		{"escaped dot", "test\\.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRegexPattern(tt.input)
			if result != tt.expected {
				t.Errorf("isRegexPattern(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}
