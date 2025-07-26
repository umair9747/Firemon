package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

type Config struct {
	Concurrency int
	OutputFile  string
	Verbose     bool
	JSONOutput  bool
}

type Result struct {
	URL        string
	Vulnerable bool
	VulnType   string
	Error      error
}

type FirebaseResponse struct {
	Error string `json:"error,omitempty"`
}

type JSONOutput struct {
	Summary JSONSummary  `json:"summary"`
	Results []JSONResult `json:"results"`
}

type JSONSummary struct {
	TotalScanned    int `json:"total_scanned"`
	VulnerableCount int `json:"vulnerable_count"`
	Concurrency     int `json:"concurrency"`
}

type JSONResult struct {
	URL          string `json:"url"`
	Vulnerable   bool   `json:"vulnerable"`
	VulnType     string `json:"vulnerability_type,omitempty"`
	ErrorMessage string `json:"error,omitempty"`
}

var config Config

func main() {
	var rootCmd = &cobra.Command{
		Use:   "firemon [url1] [url2] [file.txt]",
		Short: "A fast concurrent tool to check Firebase vulnerabilities",
		Long:  "A CLI tool that checks Firebase URLs for read access and takeover vulnerabilities",
		Run:   runFiremon,
	}

	rootCmd.Flags().IntVarP(&config.Concurrency, "concurrency", "c", 20, "Number of concurrent requests")
	rootCmd.Flags().StringVarP(&config.OutputFile, "outputFile", "o", "", "Output file to save results")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVarP(&config.JSONOutput, "json", "j", false, "Output results in JSON format")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runFiremon(cmd *cobra.Command, args []string) {
	fmt.Print(banner)

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Error: Please provide at least one URL or a file containing URLs\n")
		os.Exit(1)
	}

	urls := collectURLs(args)
	if len(urls) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No valid Firebase URLs found\n")
		os.Exit(1)
	}

	if config.Verbose {
		fmt.Printf("Processing %d URLs with concurrency %d\n", len(urls), config.Concurrency)
	}

	results := processURLsConcurrently(urls)

	outputResults(results)
}

func collectURLs(args []string) []string {
	var urls []string

	for _, arg := range args {
		if isFile(arg) {
			fileURLs, err := readURLsFromFile(arg)
			if err != nil {
				if config.Verbose {
					fmt.Fprintf(os.Stderr, "Warning: Could not read file %s: %v\n", arg, err)
				}
				continue
			}
			urls = append(urls, fileURLs...)
		} else {
			urls = append(urls, arg)
		}
	}

	var firebaseURLs []string
	for _, rawURL := range urls {
		if processedURL := processFirebaseURL(rawURL); processedURL != "" {
			firebaseURLs = append(firebaseURLs, processedURL)
		}
	}

	return firebaseURLs
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func readURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	return urls, scanner.Err()
}

func processFirebaseURL(rawURL string) string {
	lowerURL := strings.ToLower(rawURL)

	if !strings.Contains(lowerURL, ".firebaseio.com") {
		if config.Verbose {
			fmt.Printf("Skipping non-Firebase URL: %s\n", rawURL)
		}
		return ""
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		if config.Verbose {
			fmt.Printf("Skipping invalid URL: %s\n", rawURL)
		}
		return ""
	}

	rootURL := fmt.Sprintf("%s://%s/", parsedURL.Scheme, parsedURL.Host)

	if config.Verbose {
		fmt.Printf("Processing Firebase URL: %s -> %s\n", rawURL, rootURL)
	}

	return rootURL
}

func processURLsConcurrently(urls []string) []Result {
	uniqueURLs := removeDuplicates(urls)

	urlChan := make(chan string, len(uniqueURLs))
	resultChan := make(chan Result, len(uniqueURLs))

	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go worker(urlChan, resultChan, &wg)
	}

	for _, url := range uniqueURLs {
		urlChan <- url
	}
	close(urlChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []Result
	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

func removeDuplicates(urls []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, url := range urls {
		if !seen[url] {
			seen[url] = true
			unique = append(unique, url)
		}
	}

	return unique
}

func worker(urlChan <-chan string, resultChan chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for baseURL := range urlChan {
		result := checkFirebaseVulnerability(client, baseURL)
		resultChan <- result
	}
}

func checkFirebaseVulnerability(client *http.Client, baseURL string) Result {
	jsonURL := baseURL + ".json"

	if config.Verbose {
		fmt.Printf("Checking: %s\n", jsonURL)
	}

	resp, err := client.Get(jsonURL)
	if err != nil {
		return Result{
			URL:   baseURL,
			Error: err,
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{
			URL:   baseURL,
			Error: err,
		}
	}

	var firebaseResp FirebaseResponse
	if err := json.Unmarshal(body, &firebaseResp); err != nil {
		if resp.StatusCode == 200 && len(body) > 0 {
			return Result{
				URL:        baseURL,
				Vulnerable: true,
				VulnType:   "READ ACCESS",
			}
		}
		return Result{
			URL:   baseURL,
			Error: fmt.Errorf("could not parse response as JSON"),
		}
	}

	if firebaseResp.Error != "" {
		if strings.Contains(firebaseResp.Error, "404 Not Found") {
			return Result{
				URL:        baseURL,
				Vulnerable: true,
				VulnType:   "TAKEOVER",
			}
		}
		return Result{
			URL: baseURL,
		}
	}

	return Result{
		URL:        baseURL,
		Vulnerable: true,
		VulnType:   "READ ACCESS",
	}
}

func outputResults(results []Result) {
	if config.JSONOutput {
		outputJSONResults(results)
	} else {
		outputTextResults(results)
	}
}

func outputTextResults(results []Result) {
	var outputLines []string
	vulnerableCount := 0

	for _, result := range results {
		if result.Error != nil {
			if config.Verbose {
				fmt.Printf("Error checking %s: %v\n", result.URL, result.Error)
			}
			continue
		}

		if result.Vulnerable {
			vulnerableCount++
			line := fmt.Sprintf("%s [VULNERABLE : %s]", result.URL, result.VulnType)
			fmt.Println(line)
			outputLines = append(outputLines, line)
		} else if config.Verbose {
			fmt.Printf("%s [NOT VULNERABLE]\n", result.URL)
		}
	}

	if config.Verbose {
		fmt.Printf("\nScan completed. Found %d vulnerable endpoints out of %d total.\n", vulnerableCount, len(results))
	}

	if config.OutputFile != "" && len(outputLines) > 0 {
		if err := saveTextToFile(outputLines); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving to file: %v\n", err)
		} else if config.Verbose {
			fmt.Printf("Results saved to %s\n", config.OutputFile)
		}
	}
}

func outputJSONResults(results []Result) {
	var jsonResults []JSONResult
	vulnerableCount := 0

	for _, result := range results {
		jsonResult := JSONResult{
			URL:        result.URL,
			Vulnerable: result.Vulnerable,
		}

		if result.Error != nil {
			jsonResult.ErrorMessage = result.Error.Error()
		} else if result.Vulnerable {
			jsonResult.VulnType = result.VulnType
			vulnerableCount++
		}

		jsonResults = append(jsonResults, jsonResult)
	}

	jsonOutput := JSONOutput{
		Summary: JSONSummary{
			TotalScanned:    len(results),
			VulnerableCount: vulnerableCount,
			Concurrency:     config.Concurrency,
		},
		Results: jsonResults,
	}

	jsonBytes, err := json.MarshalIndent(jsonOutput, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		return
	}

	fmt.Println(string(jsonBytes))

	if config.OutputFile != "" {
		if err := saveJSONToFile(jsonBytes); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving JSON to file: %v\n", err)
		} else if config.Verbose {
			fmt.Printf("Results saved to %s\n", config.OutputFile)
		}
	}
}

func saveTextToFile(lines []string) error {
	dir := filepath.Dir(config.OutputFile)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	file, err := os.OpenFile(config.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func saveJSONToFile(jsonData []byte) error {
	dir := filepath.Dir(config.OutputFile)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	file, err := os.OpenFile(config.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	return err
}
