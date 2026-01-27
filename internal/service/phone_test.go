package service

import (
	"testing"
)

func TestPhoneNormalization(t *testing.T) {
	service := &AuthService{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Vietnam mobile with leading 0",
			input:    "0909123456",
			expected: "+84909123456",
		},
		{
			name:     "Vietnam mobile with dots",
			input:    "0909.123.456",
			expected: "+84909123456",
		},
		{
			name:     "Vietnam mobile with spaces",
			input:    "0909 123 456",
			expected: "+84909123456",
		},
		{
			name:     "Vietnam mobile with dashes",
			input:    "0909-123-456",
			expected: "+84909123456",
		},
		{
			name:     "Already E.164 format",
			input:    "+84909123456",
			expected: "+84909123456",
		},
		{
			name:     "International format without plus",
			input:    "84909123456",
			expected: "+84909123456",
		},
		{
			name:     "US phone number",
			input:    "+12025551234",
			expected: "+12025551234",
		},
		{
			name:     "Phone with parentheses",
			input:    "(090) 912-3456",
			expected: "+84909123456",
		},
		{
			name:     "Mixed format",
			input:    "+84 (0) 909 123 456",
			expected: "+84909123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.normalizePhone(tt.input)
			if result != tt.expected {
				t.Errorf("normalizePhone(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsPhoneNumber(t *testing.T) {
	service := &AuthService{}

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Valid mobile",
			input:    "0909123456",
			expected: true,
		},
		{
			name:     "Valid with country code",
			input:    "+84909123456",
			expected: true,
		},
		{
			name:     "Email address",
			input:    "test@example.com",
			expected: false,
		},
		{
			name:     "Username",
			input:    "john_doe",
			expected: false,
		},
		{
			name:     "Too short",
			input:    "1234567",
			expected: false,
		},
		{
			name:     "Too long",
			input:    "1234567890123456",
			expected: false,
		},
		{
			name:     "Valid with separators",
			input:    "090-912-3456",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.isPhoneNumber(tt.input)
			if result != tt.expected {
				t.Errorf("isPhoneNumber(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizeIdentifier(t *testing.T) {
	service := &AuthService{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Email uppercase",
			input:    "Test@Example.COM",
			expected: "test@example.com",
		},
		{
			name:     "Email with spaces",
			input:    "  test@example.com  ",
			expected: "test@example.com",
		},
		{
			name:     "Phone Vietnam",
			input:    "0909.123.456",
			expected: "+84909123456",
		},
		{
			name:     "Phone E.164",
			input:    "+84909123456",
			expected: "+84909123456",
		},
		{
			name:     "Username",
			input:    "  john_doe  ",
			expected: "john_doe",
		},
		{
			name:     "Passport",
			input:    "  N1234567  ",
			expected: "N1234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.normalizeIdentifier(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeIdentifier(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
