package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxResponseSize = 10 * 1024 * 1024 // 10MB max response size
	maxURLLength    = 2048              // Maximum URL length
)

type Config struct {
	concurrency int
	delay       time.Duration
	outputDir   string
	timeout     time.Duration
	maxSize     int64
	insecure    bool
	headers     []string
	userAgent   string
	verbose     bool
}

var config Config

func init() {
	flag.IntVar(&config.concurrency, "c", 20, "Concurrency level")
	flag.DurationVar(&config.delay, "d", 5*time.Second, "Delay between requests to the same domain")
	flag.StringVar(&config.outputDir, "o", "out", "Output directory")
	flag.DurationVar(&config.timeout, "t", 30*time.Second, "Request timeout")
	flag.Int64Var(&config.maxSize, "max-size", maxResponseSize, "Maximum response size in bytes")
	flag.BoolVar(&config.insecure, "insecure", false, "Skip SSL certificate verification")
	flag.StringVar(&config.userAgent, "ua", "concurl/2.0", "User-Agent header")
	flag.BoolVar(&config.verbose, "v", false, "Verbose output")
}

func main() {
	flag.Parse()

	// Create HTTP client with timeout
	transport := &http.Transport{
		MaxIdleConns:        config.concurrency,
		MaxIdleConnsPerHost: config.concurrency,
		MaxConnsPerHost:     config.concurrency,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.insecure,
		},
		DisableKeepAlives: false,
		IdleConnTimeout:   90 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(config.outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	jobs := make(chan string, config.concurrency*2)
	rl := newRateLimiter(config.delay)

	var wg sync.WaitGroup
	ctx := context.Background()

	// Start workers
	for i := 0; i < config.concurrency; i++ {
		wg.Add(1)
		go worker(ctx, client, jobs, rl, &wg)
	}

	// Read URLs from stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" {
			continue
		}
		if len(url) > maxURLLength {
			if config.verbose {
				fmt.Fprintf(os.Stderr, "URL too long, skipping: %s...\n", url[:50])
			}
			continue
		}
		jobs <- url
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}

	close(jobs)
	wg.Wait()
}

func worker(ctx context.Context, client *http.Client, jobs <-chan string, rl *rateLimiter, wg *sync.WaitGroup) {
	defer wg.Done()

	for rawURL := range jobs {
		if err := processURL(ctx, client, rawURL, rl); err != nil {
			if config.verbose {
				fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", rawURL, err)
			}
		}
	}
}

func processURL(ctx context.Context, client *http.Client, rawURL string, rl *rateLimiter) error {
	// Validate and parse URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	domain := parsed.Hostname()
	if domain == "" {
		domain = "unknown"
	}

	// Rate limit requests to the same domain
	rl.Block(domain)

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	// Set headers
	req.Header.Set("User-Agent", config.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response with size limit
	limited := io.LimitReader(resp.Body, config.maxSize)
	body, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	// Generate filename based on URL hash
	hash := sha256.Sum256([]byte(rawURL))
	filename := fmt.Sprintf("%x", hash)[:16]
	outputPath := filepath.Join(config.outputDir, domain, filename)

	// Create domain directory
	domainDir := filepath.Join(config.outputDir, domain)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	// Prepare output with metadata
	output := fmt.Sprintf("URL: %s\nStatus: %d\nContent-Type: %s\nContent-Length: %d\nDate: %s\n------\n\n%s",
		rawURL,
		resp.StatusCode,
		resp.Header.Get("Content-Type"),
		len(body),
		time.Now().Format(time.RFC3339),
		body)

	// Write to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	fmt.Printf("%s %d %s\n", outputPath, resp.StatusCode, rawURL)
	return nil
}