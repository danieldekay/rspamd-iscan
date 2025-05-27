package rspamc

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSpam(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		password       string
		messageBody    string
		expectedError  string
		validateRequest func(t *testing.T, r *http.Request, body string)
	}{
		{
			name: "successful learn spam",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintln(w, `{"success": true}`)
			},
			password:    "testpassword",
			messageBody: "this is a spam message",
			validateRequest: func(t *testing.T, r *http.Request, body string) {
				if r.Method != http.MethodPost {
					t.Errorf("expected POST request, got %s", r.Method)
				}
				if r.URL.Path != "/learnspam" {
					t.Errorf("expected path /learnspam, got %s", r.URL.Path)
				}
				if r.Header.Get("password") != "testpassword" {
					t.Errorf("expected password header 'testpassword', got '%s'", r.Header.Get("password"))
				}
				if body != "this is a spam message" {
					t.Errorf("expected body 'this is a spam message', got '%s'", body)
				}
			},
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "internal server error", http.StatusInternalServerError)
			},
			password:      "testpassword",
			messageBody:   "another spam message",
			expectedError: "request failed with status: 500 Internal Server Error",
		},
		{
			name: "rspamd indicates already learned (success: false)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				// Note: Current client does not treat success:false as an error
				fmt.Fprintln(w, `{"success": false, "error": "already learned"}`)
			},
			password:    "testpassword",
			messageBody: "already learned spam",
		},
		{
			name: "non-json response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprintln(w, "this is not json")
			},
			password:      "testpassword",
			messageBody:   "spam for non-json test",
			expectedError: `got response with content-type: "text/plain", expecting: "application/json"`,
		},
		{
			name: "empty response body with json content type",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK) // Send 200 OK but no body
			},
			password:      "testpassword",
			messageBody:   "spam for empty json response",
			expectedError: "EOF", // json.Decoder will hit EOF
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requestBodyStore string
			var actualRequest *http.Request

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actualRequest = r.Clone(context.Background()) // Store a copy for validation
				bodyBytes, _ := io.ReadAll(r.Body)
				requestBodyStore = string(bodyBytes)
				tt.handler(w, r)
			}))
			defer server.Close()

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			client := New(logger, server.URL, tt.password)

			err := client.Spam(context.Background(), strings.NewReader(tt.messageBody))

			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error '%s', got nil", tt.expectedError)
				}
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error to contain '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got '%s'", err.Error())
				}
			}
			
			if tt.validateRequest != nil && actualRequest != nil {
				tt.validateRequest(t, actualRequest, requestBodyStore)
			} else if tt.validateRequest != nil && actualRequest == nil && tt.expectedError == "" {
				// If we expected a request (no error expected that would prevent it) but didn't get one
				t.Errorf("expected a request to be made, but it wasn't (or an early error occurred)")
			}
		})
	}

	// Test case for request creation error (invalid URL in client)
	t.Run("request creation error due to bad client URL", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		// Provide a malformed base URL part to New. The actual URL construction happens in New.
		// sendRequest uses http.NewRequestWithContext, which can fail if the URL is bad.
		// Here, the URL is formed as server.URL + "/learnspam". If server.URL is bad, it will fail.
		// A truly malformed URL that http.NewRequestWithContext would catch might involve invalid characters.
		// Let's use a client with an empty URL, which should lead to an error in NewRequestWithContext.
		
		client := New(logger, "%", "password") // "%" is an invalid URL character
		err := client.Spam(context.Background(), strings.NewReader("test"))
		if err == nil {
			t.Fatal("expected an error for request creation failure, got nil")
		}
		// The error message from net/http is "net/http: invalid method POST" if the URL is just "%"
		// or "parse "%/learnspam": invalid URL escape "%/l""
		// Depending on how NewRequestWithContext processes it.
		// Let's check for "invalid" as a more general term.
		if !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "unsupported protocol scheme") {
			// If the client construction itself changes to validate URLs earlier, this might change.
			// For now, an empty URL in `New` leads to `http.NewRequestWithContext` failing with "unsupported protocol scheme"
			// A URL like ":" leads to "missing protocol scheme"
			// A URL like "http://invalid host" leads to dial error.
			// A URL like " %" leads to parse error.
			t.Errorf("expected error related to invalid URL or request creation, got: %s", err.Error())
		}
	})
}
