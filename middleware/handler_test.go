package middleware

import (
	"bytes"
	"encoding/json"
	"github.com/gorilla/mux"
	"io/ioutil"
	pers "kai_hiringtest/persistance"
	"kai_hiringtest/types"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Mock HTTP Client
type MockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return m.DoFunc(req)
}

func TestInithandlers(t *testing.T) {
	// Initialize handlers

	pers.InitDB()
	defer pers.DropTables()

	client = &MockHTTPClient{DoFunc: func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == "https://raw.githubusercontent.com/test-repo/vulnerability_scans/refs/heads/main/test-file1.json" {
			data, err := ioutil.ReadFile("test.json")
			if err != nil {
				log.Fatalf("Error reading file: %v", err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader(data)),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
		}, nil

	}}

	r := mux.NewRouter()
	registerhandlers(r)

	// Create a test server
	ts := httptest.NewServer(r)
	defer ts.Close()

	// Example test for /scan route
	t.Run("TestScanHandler", func(t *testing.T) {
		// Prepare a request payload
		payload := types.RequestPayload{
			Repo:  "test-repo",
			Files: []string{"test-file1.json"},
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("Error marshaling request payload: %v", err)
		}

		req, err := http.NewRequest(http.MethodPost, ts.URL+"/scan", bytes.NewReader(payloadBytes))
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Error making request: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, but got %d", http.StatusOK, resp.StatusCode)
		}
	})

	// Example test for /query route
	t.Run("TestQueryHandler", func(t *testing.T) {
		// Prepare a request payload with filter
		filter := types.Filter{Severity: "HIGH"}
		requestPayload := types.Querypayload{Filter: filter}
		payloadBytes, err := json.Marshal(requestPayload)
		if err != nil {
			t.Fatalf("Error marshaling request payload: %v", err)
		}

		req, err := http.NewRequest(http.MethodPost, ts.URL+"/query", bytes.NewReader(payloadBytes))
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}

		// expected persistance query
		expectedResults := []types.Vulnerability{
			{ID: "CVE-2024-2222", Severity: "HIGH", Description: "Test vulnerability 1"},
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Error making request: %v", err)
		}

		// Check if the response status code is OK
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status code %d, but got %d", http.StatusOK, resp.StatusCode)
		}

		var result []types.Vulnerability
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			t.Fatalf("Error decoding response: %v", err)
		}

		if len(result) != len(expectedResults) {
			t.Errorf("Expected %d vulnerabilities, but got %d", len(expectedResults), len(result))
		}
		for i, vuln := range result {
			if vuln.ID != expectedResults[i].ID || vuln.Severity != expectedResults[i].Severity {
				t.Errorf("Vulnerability mismatch at index %d: expected %+v, but got %+v", i, expectedResults[i], vuln)
			}
		}
	})
}
