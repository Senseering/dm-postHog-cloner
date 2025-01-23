package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/term"
)

// Dashboard represents the JSON structure returned by PostHog for a dashboard.
type Dashboard struct {
    ID    int                    `json:"id"`
    Name  string                 `json:"name"`
    Tiles []map[string]interface{} `json:"tiles"`
}

// promptInput reads a line from stdin. If required==true, it keeps prompting until the user provides input.
func promptInput(promptText string, required bool) (string, error) {
    reader := bufio.NewReader(os.Stdin)

    for {
        fmt.Print(promptText)
        input, err := reader.ReadString('\n')
        if err != nil {
            return "", err
        }
        input = strings.TrimSpace(input)
        if input == "" && required {
            fmt.Println("This field is required. Please provide a valid input.")
            continue
        }
        return input, nil
    }
}

// promptPassword hides typed text and returns the input as a string.
func promptPassword(promptText string) (string, error) {
    fmt.Print(promptText)
    bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
    if err != nil {
        return "", err
    }
    fmt.Println()
    return strings.TrimSpace(string(bytePassword)), nil
}

// createHTTPClient returns an *http.Client configured with optional SSL verification settings.
func createHTTPClient(disableSSL bool, certPath string) (*http.Client, error) {
    tlsConfig := &tls.Config{}

    if disableSSL {
        fmt.Println("[WARNING] SSL certificate verification is disabled.")
        tlsConfig.InsecureSkipVerify = true
    } else if certPath != "" {
        // Load a custom certificate
        caCert, err := os.ReadFile(certPath)
        if err != nil {
            return nil, fmt.Errorf("[ERROR] Could not read certificate at %s: %w", certPath, err)
        }
        caCertPool := x509.NewCertPool()
        if !caCertPool.AppendCertsFromPEM(caCert) {
            return nil, errors.New("[ERROR] Failed to append certificate to pool")
        }
        fmt.Printf("[INFO] Using custom SSL cert at %s.\n", certPath)
        tlsConfig.RootCAs = caCertPool
    } else {
        fmt.Println("[INFO] Using default SSL verification.")
    }

    transport := &http.Transport{TLSClientConfig: tlsConfig}
    return &http.Client{Transport: transport}, nil
}

// retrieveDashboard fetches a PostHog dashboard by ID, returning its name and tile data.
func retrieveDashboard(client *http.Client, apiKey, projectID, dashboardID string) (string, []map[string]interface{}, error) {
    url := fmt.Sprintf("https://eu.posthog.com/api/projects/%s/dashboards/%s", projectID, dashboardID)

    req, err := http.NewRequest(http.MethodGet, url, nil)
    if err != nil {
        return "", nil, err
    }
    req.Header.Set("Authorization", "Bearer "+apiKey)

    resp, err := client.Do(req)
    if err != nil {
        return "", nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return "", nil, fmt.Errorf("retrieveDashboard: received non-200 status: %d\nBody: %s", resp.StatusCode, string(bodyBytes))
    }

    var dash Dashboard
    if err := json.NewDecoder(resp.Body).Decode(&dash); err != nil {
        return "", nil, fmt.Errorf("retrieveDashboard: failed to parse JSON: %w", err)
    }

    fmt.Printf("[INFO] Retrieved dashboard '%s' with %d tile(s) from Project ID %s.\n",
        dash.Name, len(dash.Tiles), projectID)

    return dash.Name, dash.Tiles, nil
}

// createDashboard creates a new, empty dashboard in the specified project.
func createDashboard(client *http.Client, apiKey, projectID, dashboardName string) (int, error) {
    urlStr := fmt.Sprintf("https://eu.posthog.com/api/projects/%s/dashboards/", projectID)

    data := url.Values{}
    data.Set("name", dashboardName)

    req, err := http.NewRequest(http.MethodPost, urlStr, strings.NewReader(data.Encode()))
    if err != nil {
        return 0, err
    }
    req.Header.Set("Authorization", "Bearer "+apiKey)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := client.Do(req)
    if err != nil {
        return 0, err
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode > 299 {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return 0, fmt.Errorf("createDashboard: received non-2xx status: %d\nBody: %s", resp.StatusCode, string(bodyBytes))
    }

    var dash Dashboard
    if err := json.NewDecoder(resp.Body).Decode(&dash); err != nil {
        return 0, fmt.Errorf("createDashboard: failed to parse response JSON: %w", err)
    }

    fmt.Printf("[INFO] Created new dashboard '%s' with ID %d in Project ID %s.\n",
        dashboardName, dash.ID, projectID)

    return dash.ID, nil
}

// updateDashboard patches the newly-created dashboard with the original tile references.
func updateDashboard(client *http.Client, apiKey, projectID string, dashboardID int, tiles []map[string]interface{}) error {
    urlStr := fmt.Sprintf("https://eu.posthog.com/api/projects/%s/dashboards/%d", projectID, dashboardID)

    payload := map[string]interface{}{
        "tiles": tiles,
    }
    payloadBytes, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("updateDashboard: failed to marshal payload: %w", err)
    }

    req, err := http.NewRequest(http.MethodPatch, urlStr, bytes.NewBuffer(payloadBytes))
    if err != nil {
        return err
    }
    req.Header.Set("Authorization", "Bearer "+apiKey)
    req.Header.Set("Content-Type", "application/json")

    fmt.Printf("[DEBUG] Patching new dashboard with %d tile(s).\n", len(tiles))

    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode > 299 {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("updateDashboard: received non-2xx status: %d\nBody: %s", resp.StatusCode, string(bodyBytes))
    }

    fmt.Printf("[INFO] Dashboard ID %d in Project ID %s updated with %d tiles.\n", dashboardID, projectID, len(tiles))
    fmt.Println("[SUCCESS] Dashboard cloned (moved) successfully.")
    return nil
}

func main() {
    // pass `-noninteractive` for debugging/when you using e.g., env vars.
    nonInteractive := flag.Bool("noninteractive", false, "Run without prompting for input.")
    flag.Parse()

    fmt.Println("=== PostHog Simple Dashboard Cloner ===")
    fmt.Println("**WARNING**: This script copies tiles by ID, which *moves* them from Project A -> Project B.")
    fmt.Println("To avoid losing tiles in your original dashboard, first DUPLICATE that dashboard")
    fmt.Println("in Project A, then run this script on the *duplicated* dashboard.")

    var apiKey, sourceProjectID, sourceDashboardID, destinationProjectID, certPath string
    var disableSSL bool
    var err error

    if *nonInteractive {
        // could parse these from .env, flags, or config files.
        apiKey = os.Getenv("PH_API_KEY")
        sourceProjectID = os.Getenv("SOURCE_PROJECT_ID")
        sourceDashboardID = os.Getenv("SOURCE_DASHBOARD_ID")
        destinationProjectID = os.Getenv("DESTINATION_PROJECT_ID")
        certPath = os.Getenv("SSL_CERT_PATH")
        sslDisableStr := os.Getenv("DISABLE_SSL")
        disableSSL = (strings.ToLower(sslDisableStr) == "true")
    } else {
        // Interactive approach
        if apiKey, err = promptPassword("Enter your PostHog Personal API Key: "); err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }
        if sourceProjectID, err = promptInput("Enter the Source Project ID (Project A, the *duplicated* dashboard): ", true); err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }
        if sourceDashboardID, err = promptInput("Enter the Source Dashboard ID (the *duplicated* dashboard): ", true); err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }
        if destinationProjectID, err = promptInput("Enter the Destination Project ID (Project B): ", true); err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }
        if certPath, err = promptInput("Enter path to SSL certificate (press Enter to skip): ", false); err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }

        for {
            choice, err2 := promptInput("Disable SSL certificate verification? (y/n): ", true)
            if err2 != nil {
                fmt.Fprintln(os.Stderr, err2)
                os.Exit(1)
            }
            choice = strings.ToLower(strings.TrimSpace(choice))
            if choice == "y" || choice == "yes" {
                disableSSL = true
                break
            } else if choice == "n" || choice == "no" {
                disableSSL = false
                break
            } else {
                fmt.Println("Please enter 'y' or 'n'.")
            }
        }

        fmt.Println("\nYou are about to move tiles from Project A to Project B.")
        fmt.Println("This will remove the tiles from the source dashboard in Project A!")
        confirm, err3 := promptInput("Are you sure you duplicated the source dashboard in A first? (y/n): ", true)
        if err3 != nil {
            fmt.Fprintln(os.Stderr, err3)
            os.Exit(1)
        }
        if !strings.HasPrefix(strings.ToLower(confirm), "y") {
            fmt.Println("Operation cancelled.")
            os.Exit(0)
        }
    }

    // Create custom HTTP client
    httpClient, err := createHTTPClient(disableSSL, certPath)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    // Retrieve the (duplicated) source dashboard from Project A
    dashboardName, tiles, err := retrieveDashboard(httpClient, apiKey, sourceProjectID, sourceDashboardID)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    // Create a new empty dashboard in Project B
    newDashboardID, err := createDashboard(httpClient, apiKey, destinationProjectID, dashboardName)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    // Patch new dashboard with the original tile references
    if err := updateDashboard(httpClient, apiKey, destinationProjectID, newDashboardID, tiles); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
