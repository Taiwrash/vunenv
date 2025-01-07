package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanDirectory(t *testing.T) {
	// Create a temporary directory
	dir := t.TempDir()

	// Create a temporary file with some content
	file, err := os.Create(filepath.Join(dir, "test.js"))
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(`process.env.TEST_ENV`)
	if err != nil {
		t.Fatalf("Failed to write to test file: %v", err)
	}

	// Run the scanner
	err = scanDirectory(dir)
	if err != nil {
		t.Fatalf("scanDirectory failed: %v", err)
	}

	// Check if vulnerabilities were detected
	if len(vulnerabilities) == 0 {
		t.Fatal("Expected vulnerabilities to be detected, but none were found")
	}

	// Check the details of the detected vulnerability
	vuln := vulnerabilities[0]
	if vuln.File != file.Name() {
		t.Errorf("Expected file %s, but got %s", file.Name(), vuln.File)
	}
	if vuln.Line != 1 {
		t.Errorf("Expected line 1, but got %d", vuln.Line)
	}
	if vuln.Code != "process.env.TEST_ENV" {
		t.Errorf("Expected code 'process.env.TEST_ENV', but got '%s'", vuln.Code)
	}
}

func TestGenerateHTMLReport(t *testing.T) {
	vulnerabilities := []Vulnerability{
		{File: "test.js", Line: 1, Code: "process.env.TEST_ENV"},
	}

	err := generateHTMLReport("test_report.html", vulnerabilities)
	if err != nil {
		t.Fatalf("generateHTMLReport failed: %v", err)
	}

	// Check if the report file was created
	if _, err := os.Stat("test_report.html"); os.IsNotExist(err) {
		t.Fatal("Expected report file to be created, but it does not exist")
	}

	// Clean up
	os.Remove("test_report.html")
}
