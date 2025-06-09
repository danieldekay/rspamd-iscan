package rspamc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

type Client struct {
	checkURL string
	hamURL   string
	spamURL  string
	logger   *slog.Logger
	password string
}

func New(logger *slog.Logger, url, password string) *Client {
	return &Client{
		checkURL: url + "/checkv2",
		hamURL:   url + "/learnham",
		spamURL:  url + "/learnspam",
		logger:   logger.WithGroup("rspamc").With("server", url),
		password: password,
	}
}

func (c *Client) sendRequest(ctx context.Context, url string, msg io.Reader, result any) error {
	logger := c.logger.With("url", url)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, msg)
	if err != nil {
		return nil
	}

	req.Header.Add("password", c.password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		// TODO: check content length, set max. size of body to read
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Error("rspamc reading http error body failed", "error", err)
		}
		logger.Debug("rspamc http response", "body", string(buf), "status", resp.Status)
		if resp.StatusCode >= 200 && resp.StatusCode <= 300 {
			return nil
		}
		return fmt.Errorf("request failed with status: %s", resp.Status)
	}

	const contentTypeJSON = "application/json"
	ctype := resp.Header.Get("Content-Type")
	if ctype != contentTypeJSON {
		// TODO: cancel context first
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("got response with content-type: %q, expecting: %q", ctype, contentTypeJSON)
	}

	if result == nil {
		buf, err := io.ReadAll(resp.Body)
		if err != nil {
			logger.Error("rspamc reading http error body failed", "error", err)
		}
		if len(buf) != 0 {
			logger.Warn("expected no response body but got one", "response", string(buf))
		}
		return nil
	}

	err = json.NewDecoder(resp.Body).Decode(result)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Check(ctx context.Context, msg io.Reader) (*Result, error) {
	var result Result
	err := c.sendRequest(ctx, c.checkURL, msg, &result)
	if err != nil {
		return nil, err
	}
	return &result, err
}

func (c *Client) Ham(ctx context.Context, msg io.Reader) error {
	var resp learnHamReponse

	err := c.sendRequest(ctx, c.hamURL, msg, &resp)
	if err != nil {
		return err
	}

	// resp code 208 == already learned, returns an json with an "error"
	// field

	// It is also unsuccessful if the same message has already learned
	// before
	// if !resp.Success {
	// 	return errors.New("unsuccessful")
	// }

	return nil
}

func (c *Client) Spam(ctx context.Context, msg io.Reader) error {
	var resp learnHamReponse // Assuming learnSpamResponse is similar to learnHamReponse

	err := c.sendRequest(ctx, c.spamURL, msg, &resp)
	if err != nil {
		return err
	}

	// Similar to Ham, we can check resp.Success if needed,
	// but for now, we'll keep it simple.
	// if !resp.Success {
	// 	return errors.New("unsuccessful")
	// }

	return nil
}

type learnHamReponse struct {
	Success bool `json:"success"`
}

type Result struct {
	Action    string            `json:"action"`
	Score     float32           `json:"score"`
	IsSkipped bool              `json:"is_skipped"`
	Symbols   map[string]Symbol `json:"symbols"`
	// New fields for more detailed Rspamd information
	RequiredScore float32       `json:"required_score"`
	MessageID     string        `json:"message-id"`
	Milter        MilterHeaders `json:"milter"`
}

// AddHeaderEntry defines the structure for individual header modifications by Milter.
type AddHeaderEntry struct {
	Value string `json:"value"`
	Order int64  `json:"order"` // Assuming 'order' is an integer; if it can be float, float64 might be better.
}

// MilterHeaders defines the structure for Milter header modifications.
type MilterHeaders struct {
	AddHeaders map[string]AddHeaderEntry `json:"add_headers"`
	// RemoveHeaders map[string]int64 `json:"remove_headers"` // Example for future extension
}

// https://rspamd.com/doc/architecture/protocol.html#protocol-basics
type Symbol struct {
	Name  string  `json:"name"`
	Score float32 `json:"score"`
}

// GetHeadersToApply constructs a map of HTTP-like headers based on the Rspamd result.
// Milter headers take precedence over standard constructed headers if names clash.
func (r *Result) GetHeadersToApply() map[string]string {
	headers := make(map[string]string)

	// Process Milter Headers first
	if r.Milter.AddHeaders != nil {
		for name, entry := range r.Milter.AddHeaders {
			headers[name] = entry.Value
		}
	}

	// Construct Standard Headers only if score > 0
	if r.Score > 0 {
		// X-Spam-Flag
		if _, exists := headers["X-Spam-Flag"]; !exists {
			headers["X-Spam-Flag"] = "YES"
		}

		// X-Rspamd-Score
		if _, exists := headers["X-Rspamd-Score"]; !exists {
			headers["X-Rspamd-Score"] = fmt.Sprintf("%.2f", r.Score)
		}

		// X-Rspamd-Required-Score
		if _, exists := headers["X-Rspamd-Required-Score"]; !exists {
			// Only add if RequiredScore is meaningful (not zero, assuming zero means not set or not applicable)
			// Rspamd might send 0.0 for some configurations, so this check might need adjustment
			// based on typical Rspamd behavior. For now, any non-zero value is considered meaningful.
			if r.RequiredScore != 0 {
				headers["X-Rspamd-Required-Score"] = fmt.Sprintf("%.2f", r.RequiredScore)
			}
		}

		// X-Spamd-Bar
		if _, exists := headers["X-Spamd-Bar"]; !exists {
			barLength := int(r.Score)
			if r.Score > 0 && barLength == 0 { // For scores like 0.1 to 0.9, give one '+'
				barLength = 1
			}
			const maxBarLength = 20
			if barLength > maxBarLength {
				barLength = maxBarLength
			}
			if barLength < 0 { // Should not happen with score > 0, but defensive
				barLength = 0
			}
			bar := ""
			for i := 0; i < barLength; i++ {
				bar += "+"
			}
			if bar != "" { // Only add if there's something to show
				headers["X-Spamd-Bar"] = bar
			}
		}

		// X-Rspamd-Symbols
		if _, exists := headers["X-Rspamd-Symbols"]; !exists {
			if len(r.Symbols) > 0 {
				symbolNames := make([]string, 0, len(r.Symbols))
				for name := range r.Symbols {
					symbolNames = append(symbolNames, name)
				}
				// Consider sorting symbolNames for consistent output if needed, though not specified.
				headers["X-Rspamd-Symbols"] = fmt.Sprintf("%s", symbolNames) // Default Go string format for slice is not comma separated
				// Correcting to join symbols with comma and space
				symbolsStr := ""
				for i, name := range symbolNames {
					if i > 0 {
						symbolsStr += ", "
					}
					symbolsStr += name
				}
				if symbolsStr != "" {
					headers["X-Rspamd-Symbols"] = symbolsStr
				}
			}
		}

		// X-Rspamd-Action
		if _, exists := headers["X-Rspamd-Action"]; !exists {
			if r.Action != "" {
				headers["X-Rspamd-Action"] = r.Action
			}
		}

		// X-Rspamd-Message-ID
		if _, exists := headers["X-Rspamd-Message-ID"]; !exists {
			if r.MessageID != "" {
				headers["X-Rspamd-Message-ID"] = r.MessageID
			}
		}
	} else { // Handle r.Score <= 0 case for X-Spam-Flag if not set by Milter
		if _, exists := headers["X-Spam-Flag"]; !exists {
			// If score is 0 or less, and action is "no action" (or generally not spam)
			// This part of the logic for "NO" was mentioned with "r.Score == 0 and r.Action == "no action""
			// If score is <=0, it's generally "NO" unless Milter overrides.
			headers["X-Spam-Flag"] = "NO"
		}
	}

	return headers
}
