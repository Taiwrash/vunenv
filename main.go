package main

import (
	"bufio"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Vulnerability represents a detected issue
type Vulnerability struct {
	File string
	Line int
	Code string
}

// ReportData holds the data for the HTML report
type ReportData struct {
	GeneratedAt     string
	Vulnerabilities []Vulnerability
}

var vulnerabilities []Vulnerability

func main() {
	// Specify the directory to scan
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <directory_to_scan>")
		return
	}

	directoryToScan := os.Args[1]
	fmt.Println("Scanning directory:", directoryToScan)

	// Run the scanner
	err := scanDirectory(directoryToScan)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Generate HTML report
	err = generateHTMLReport("report.html", vulnerabilities)
	if err != nil {
		fmt.Println("Error generating report:", err)
		return
	}

	fmt.Println("Report generated: report.html")
}

// scanDirectory walks through the directory and inspects each file
func scanDirectory(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process specific file types
		if strings.HasSuffix(info.Name(), ".js") || strings.HasSuffix(info.Name(), ".ts") || strings.HasSuffix(info.Name(), ".go") || strings.HasSuffix(info.Name(), ".py") {
			err := inspectFile(path)
			if err != nil {
				fmt.Printf("Error inspecting file %s: %v\n", path, err)
			}
		}
		return nil
	})
}

// inspectFile scans a single file for vulnerable patterns
func inspectFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Define regex patterns for environment variable usage
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`process\.env\.[A-Z_]+`),    // Node.js/Frontend
		regexp.MustCompile(`window\.__ENV__\.[A-Z_]+`), // Custom frontend
		regexp.MustCompile(`os\.environ\['[A-Z_]+']`),  // Python
		regexp.MustCompile(`os\.Getenv\("[A-Z_]+\"\)`), // Go
	}

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		for _, pattern := range patterns {
			if pattern.MatchString(line) {
				vulnerabilities = append(vulnerabilities, Vulnerability{
					File: path,
					Line: lineNumber,
					Code: strings.TrimSpace(line),
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// generateHTMLReport creates an HTML report from vulnerabilities
func generateHTMLReport(filename string, vulnerabilities []Vulnerability) error {
	reportData := ReportData{
		GeneratedAt:     time.Now().Format("2006-01-02 15:04:05"),
		Vulnerabilities: vulnerabilities,
	}

	// HTML template for the report
	const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f4f4f4; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>Code Environment Variables Vulnerability Scan Report</h1>
    <p>Generated at: {{ .GeneratedAt }}</p>
    <table>
        <thead>
            <tr>
                <th>File</th>
                <th>Line</th>
                <th>Code</th>
            </tr>
        </thead>
        <tbody>
            {{ range .Vulnerabilities }}
            <tr>
                <td>{{ .File }}</td>
                <td>{{ .Line }}</td>
                <td><pre>{{ .Code }}</pre></td>
            </tr>
            {{ end }}
        </tbody>
    </table>
</body>
</html>
`
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, reportData)
}
