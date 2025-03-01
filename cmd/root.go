/*
Copyright © 2025 whoisnjoguu info@whoisnjoguu.com
*/

package cmd

import (
	"os"
 	"crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "strings"
    "time"
	"github.com/spf13/cobra"
)



// Flag variables
var outputFile string
var format string
var timeout int
var insecure bool

// ScanResult represents the result of scanning a URL
type ScanResult struct {
    URL            string            `json:"url"`
    StatusCode     int               `json:"status_code"`
    SQLInjection   bool              `json:"sql_injection"`
    XSSVulnerable  bool              `json:"xss_vulnerable"`
    SecurityHeaders map[string]string `json:"security_headers"`
    ResponseTime   time.Duration     `json:"response_time"`
}

// Scanner performs vulnerability scanning
type Scanner struct {
    client  *http.Client
    payloads []string
}


// creates a new Scanner with the specified timeout and TLS settings
func NewScanner(timeout time.Duration, insecure bool) *Scanner {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
    }
    return &Scanner{
        client: &http.Client{
            Transport: tr,
            Timeout:   timeout,
        },
        payloads: []string{
            "' OR '1'='1",               // SQL Injection test
            "<script>alert('xss')</script>", // XSS test
            "1; DROP TABLE users",       // Another SQLi test
        },
    }
}

// scans a target URL for vulnerabilities
func (s *Scanner) ScanURL(targetURL string) ScanResult {
    start := time.Now()
    result := ScanResult{
        URL:            targetURL,
        SecurityHeaders: make(map[string]string),
    }

    resp, err := s.client.Get(targetURL)
    if err != nil {
        log.Printf("Error accessing URL %s: %v", targetURL, err)
        return result
    }
    defer resp.Body.Close()

    result.StatusCode = resp.StatusCode
    result.ResponseTime = time.Since(start)

    // Check security headers
    headersToCheck := []string{
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
    }
    for _, header := range headersToCheck {
        if value := resp.Header.Get(header); value != "" {
            result.SecurityHeaders[header] = value
        }
    }

    // Test for vulnerabilities
    parsedURL, _ := url.Parse(targetURL)
    params := parsedURL.Query()
    for _, payload := range s.payloads {
        params.Set("test", payload)
        parsedURL.RawQuery = params.Encode()
        testResp, err := s.client.Get(parsedURL.String())
        if err != nil {
            continue
        }
        defer testResp.Body.Close()

        body, err := io.ReadAll(testResp.Body)
        if err != nil {
            continue
        }
        bodyStr := string(body)
        if strings.Contains(payload, "'") && (strings.Contains(bodyStr, "SQL") || strings.Contains(bodyStr, "syntax error")) {
            result.SQLInjection = true
        } else if strings.Contains(payload, "<script>") && strings.Contains(bodyStr, payload) {
            result.XSSVulnerable = true
        }
    }

    return result
}

// prints results in text format
func printTextResults(w io.Writer, result ScanResult) {
    fmt.Fprintf(w, "\nScan Results for: %s\n", result.URL)
    fmt.Fprintf(w, "Status Code: %d\n", result.StatusCode)
    fmt.Fprintf(w, "Response Time: %v\n", result.ResponseTime)
    fmt.Fprintf(w, "SQL Injection Vulnerable: %v\n", result.SQLInjection)
    fmt.Fprintf(w, "XSS Vulnerable: %v\n", result.XSSVulnerable)
    fmt.Fprintln(w, "Security Headers:")
    if len(result.SecurityHeaders) == 0 {
        fmt.Fprintln(w, "  No security headers found!")
    } else {
        for header, value := range result.SecurityHeaders {
            fmt.Fprintf(w, "  %s: %s\n", header, value)
        }
    }
    fmt.Fprintln(w, "------------------------")
}

// prints results in JSON format
func printJSONResults(w io.Writer, results []ScanResult) error {
    encoder := json.NewEncoder(w)
    return encoder.Encode(results)
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
    Use:   "apisecure [flags] <url1> [<url2> ...]",
    Short: "A CLI tool to scan APIs for vulnerabilities",
    Long: `apisecure is a command-line tool to scan API endpoints for common vulnerabilities
such as SQL Injection and XSS, and check for security headers.`,
    Args: cobra.MinimumNArgs(1), // Require at least one URL
    Run: func(cmd *cobra.Command, args []string) {
        // Initialize scanner with flag values
        scanner := NewScanner(time.Duration(timeout)*time.Second, insecure)
        results := make([]ScanResult, 0, len(args))

        // Scan each URL
        for _, url := range args {
            result := scanner.ScanURL(url)
            results = append(results, result)
        }

        // Determine output destination
        var out io.Writer = os.Stdout
        if outputFile != "" {
            f, err := os.Create(outputFile)
            if err != nil {
                log.Fatalf("Error creating output file: %v", err)
            }
            defer f.Close()
            out = f
        }

        // Output results based on format
        switch format {
        case "json":
            if err := printJSONResults(out, results); err != nil {
                log.Fatalf("Error writing JSON output: %v", err)
            }
        case "text":
            for _, result := range results {
                printTextResults(out, result)
            }
        default:
            log.Fatalf("Unsupported format: %s. Use 'text' or 'json'", format)
        }
    },
}

func init() {
	// Define flags
    rootCmd.Flags().StringVar(&outputFile, "o", "", "Output file to save results")
    rootCmd.Flags().StringVar(&format, "format", "text", "Output format: text or json")
    rootCmd.Flags().IntVar(&timeout, "timeout", 10, "HTTP timeout in seconds")
    rootCmd.Flags().BoolVar(&insecure, "insecure", false, "Skip TLS certificate verification")
}

// Execute runs the root command
func Execute() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
