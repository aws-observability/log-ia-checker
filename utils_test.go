package main

import (
	"os"
	"reflect"
	"testing"
)

func TestParseLogGroupArns(t *testing.T) {
	tests := []struct {
		name     string
		logArns  []string
		expected []string
	}{
		{
			name: "Valid ARNs",
			logArns: []string{
				"arn:aws:logs:us-west-2:123456789012:log-group:my-log-group",
				"arn:aws:logs:us-east-1:123456789012:log-group:another-log-group",
			},
			expected: []string{
				"my-log-group",
				"another-log-group",
			},
		},
		{
			name:     "Empty list",
			logArns:  []string{},
			expected: nil,
		},
		{
			name: "Invalid ARNs",
			logArns: []string{
				"invalid-arn",
				"arn:aws:logs:us-west-2:123456789012:not-a-log-group",
			},
			expected: nil,
		},
		{
			name: "Mixed valid and invalid ARNs",
			logArns: []string{
				"arn:aws:logs:us-west-2:123456789012:log-group:valid-group",
				"invalid-arn",
			},
			expected: []string{
				"valid-group",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLogGroupArns(tt.logArns)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseLogGroupArns() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseLogGroupArn(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected string
	}{
		{
			name:     "Valid ARN",
			arn:      "arn:aws:logs:us-west-2:123456789012:log-group:my-log-group",
			expected: "my-log-group",
		},
		{
			name:     "Invalid ARN",
			arn:      "invalid-arn",
			expected: "",
		},
		{
			name:     "Empty ARN",
			arn:      "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLogGroupArn(&tt.arn)
			if result != tt.expected {
				t.Errorf("parseLogGroupArn() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestWriteToFile(t *testing.T) {
	// Create a temporary file for testing
	tempFile := "test_output.txt"
	defer os.Remove(tempFile) // Clean up after test

	tests := []struct {
		name     string
		lines    []string
		expected []string
	}{
		{
			name:     "Write multiple lines",
			lines:    []string{"line1", "line2", "line3"},
			expected: []string{"line1", "line2", "line3"},
		},
		{
			name:     "Write empty list",
			lines:    []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write to file
			err := writeToFile(tempFile, tt.lines)
			if err != nil {
				t.Fatalf("writeToFile() error = %v", err)
			}

			// Read the file back to verify contents
			content, err := os.ReadFile(tempFile)
			if err != nil {
				t.Fatalf("Failed to read test file: %v", err)
			}

			// Check if file content matches expected
			expected := ""
			for _, line := range tt.expected {
				expected += line + "\n"
			}

			if string(content) != expected {
				t.Errorf("File content = %v, want %v", string(content), expected)
			}
		})
	}
}

func TestReplicate(t *testing.T) {
	tests := []struct {
		name     string
		char     rune
		count    int
		expected []rune
	}{
		{
			name:     "Replicate equals sign",
			char:     '=',
			count:    5,
			expected: []rune{'=', '=', '=', '=', '='},
		},
		{
			name:     "Replicate space",
			char:     ' ',
			count:    3,
			expected: []rune{' ', ' ', ' '},
		},
		{
			name:     "Zero count",
			char:     'x',
			count:    0,
			expected: []rune{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := replicate(tt.char, tt.count)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("replicate() = %v, want %v", string(result), string(tt.expected))
			}
		})
	}
}