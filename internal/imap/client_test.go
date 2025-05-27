package imap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fho/rspamd-scan/internal/rspamc"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// --- Mocks ---

// MockRspamcClient is a mock for rspamc.Client
type MockRspamcClient struct {
	SpamFunc func(ctx context.Context, msg io.Reader) error
	HamFunc  func(ctx context.Context, msg io.Reader) error
	CheckFunc func(ctx context.Context, msg io.Reader) (*rspamc.Result, error)
}

func (m *MockRspamcClient) Spam(ctx context.Context, msg io.Reader) error {
	if m.SpamFunc != nil {
		return m.SpamFunc(ctx, msg)
	}
	return nil
}

func (m *MockRspamcClient) Ham(ctx context.Context, msg io.Reader) error {
	if m.HamFunc != nil {
		return m.HamFunc(ctx, msg)
	}
	return nil
}

func (m *MockRspamcClient) Check(ctx context.Context, msg io.Reader) (*rspamc.Result, error) {
	if m.CheckFunc != nil {
		return m.CheckFunc(ctx, msg)
	}
	return nil, nil
}

// MockImapClient is a mock for imapclient.Client
// We will need to expand this mock as we test more methods.
type MockImapClient struct {
	SelectFunc func(mailbox string, options *imap.SelectOptions) *imapclient.SelectCommand
	FetchFunc  func(numSet imap.NumSet, options *imap.FetchOptions) *imapclient.FetchCommand
	MoveFunc   func(numSet imap.UIDSet, dest string) *imapclient.MoveCommand
	IdleFunc   func() (*imapclient.IdleCommand, error)
	LoginFunc  func(username string, password string) *imapclient.Command // Not strictly needed for ProcessLearnSpam but good for NewClient
	CloseFunc  func() error // Not strictly needed for ProcessLearnSpam
	
	// Store calls to verify
	SelectedMailbox string
	FetchedNumSet   imap.NumSet
	MovedUIDSet     imap.UIDSet
	MovedDest       string
}

func (m *MockImapClient) Select(mailbox string, options *imap.SelectOptions) *imapclient.SelectCommand {
	m.SelectedMailbox = mailbox
	if m.SelectFunc != nil {
		return m.SelectFunc(mailbox, options)
	}
	// Return a dummy command that does nothing and returns basic data
	cmd := imapclient.NewSelectCommand(&imap.SelectData{NumMessages: 0})
	go func() {
		cmd.SetData(&imap.SelectData{NumMessages: 0}) // Ensure data is set before Wait() can be called
		cmd.Close() 
	}()
	return cmd
}

func (m *MockImapClient) Fetch(numSet imap.NumSet, options *imap.FetchOptions) *imapclient.FetchCommand {
	m.FetchedNumSet = numSet
	if m.FetchFunc != nil {
		return m.FetchFunc(numSet, options)
	}
	// Return a dummy command that yields no messages
	cmd := imapclient.NewFetchCommand(nil) // Pass nil as client, as it's not used by FetchCommand itself for basic ops
	go func() {
		cmd.Close() // Close immediately, indicating no messages
	}()
	return cmd
}

func (m *MockImapClient) Move(uidSet imap.UIDSet, dest string) *imapclient.MoveCommand {
	m.MovedUIDSet = uidSet
	m.MovedDest = dest
	if m.MoveFunc != nil {
		return m.MoveFunc(uidSet, dest)
	}
	cmd := imapclient.NewMoveCommand(nil, uidSet, dest)
	go func() {
		cmd.Close()
	}()
	return cmd
}

func (m *MockImapClient) Idle() (*imapclient.IdleCommand, error) {
	if m.IdleFunc != nil {
		return m.IdleFunc()
	}
	return nil, errors.New("Idle not implemented in mock")
}

func (m *MockImapClient) Login(username string, password string) *imapclient.Command {
    if m.LoginFunc != nil {
        return m.LoginFunc(username, password)
    }
    cmd := imapclient.NewCommand(nil) // Pass nil as client
    go func() {
        cmd.Close() 
    }()
    return cmd
}

func (m *MockImapClient) Close() error {
    if m.CloseFunc != nil {
        return m.CloseFunc()
    }
    return nil
}

// --- Helper to create a Client with mocks ---
func newTestClient(mockImapClt *MockImapClient, mockRspamcClt *MockRspamcClient, learnSpamMailbox string) *Client {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Client{
		clt:                   mockImapClt,
		logger:                logger,
		rspamc:                mockRspamcClt,
		learnSpamMailbox:      learnSpamMailbox,
		spamMailbox:           "Spam", // Default for testing move operations
		hamLearnCheckInterval: 30 * time.Minute, // Default, not relevant for this specific test
		eventCh:               make(chan eventNewMessages, 1), // Default
	}
}

// --- Tests ---

func TestProcessLearnSpam(t *testing.T) {
	t.Run("learnSpamMailbox not configured", func(t *testing.T) {
		mockImap := &MockImapClient{}
		mockRspamc := &MockRspamcClient{}
		client := newTestClient(mockImap, mockRspamc, "") // learnSpamMailbox is empty

		err := client.ProcessLearnSpam()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if mockImap.SelectedMailbox != "" {
			t.Errorf("expected no mailbox to be selected, but '%s' was selected", mockImap.SelectedMailbox)
		}
		// Add more assertions if Rspamc.Spam was called, etc. (it shouldn't be)
		var spamCalled bool
		mockRspamc.SpamFunc = func(ctx context.Context, msg io.Reader) error {
			spamCalled = true
			return nil
		}
		_ = client.ProcessLearnSpam() // Call again to ensure SpamFunc check works
		if spamCalled {
			t.Error("Rspamc.Spam should not have been called")
		}
	})

	t.Run("learnSpamMailbox is empty (no messages)", func(t *testing.T) {
		mockImap := &MockImapClient{}
		mockRspamc := &MockRspamcClient{}
		
		mockImap.SelectFunc = func(mailbox string, options *imap.SelectOptions) *imapclient.SelectCommand {
			if mailbox != "LearnSpamFolder" {
				t.Errorf("expected selection of 'LearnSpamFolder', got '%s'", mailbox)
			}
			cmd := imapclient.NewSelectCommand(nil)
			go func() {
				cmd.SetData(&imap.SelectData{NumMessages: 0}) // No messages
				cmd.Close()
			}()
			return cmd
		}

		client := newTestClient(mockImap, mockRspamc, "LearnSpamFolder")
		err := client.ProcessLearnSpam()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		var spamCalled bool
		mockRspamc.SpamFunc = func(ctx context.Context, msg io.Reader) error {
			spamCalled = true
			return nil
		}
		_ = client.ProcessLearnSpam() // Call again to ensure SpamFunc check works
		if spamCalled {
			t.Error("Rspamc.Spam should not have been called as mailbox is empty")
		}
		if mockImap.MovedUIDSet != nil {
			t.Error("Move should not have been called as mailbox is empty")
		}
	})

	t.Run("success path (fetch, learn, move)", func(t *testing.T) {
		mockImap := &MockImapClient{}
		mockRspamc := &MockRspamcClient{}
		
		var spamFuncCalled bool
		var movedUIDs imap.UIDSet
		var movedToMailbox string

		// Mock Select
		mockImap.SelectFunc = func(mailbox string, options *imap.SelectOptions) *imapclient.SelectCommand {
			if mailbox != "LearnSpamSource" {
				t.Fatalf("expected selection of 'LearnSpamSource', got '%s'", mailbox)
			}
			cmd := imapclient.NewSelectCommand(nil)
			go func() {
				cmd.SetData(&imap.SelectData{NumMessages: 1}) // 1 message
				cmd.Close()
			}()
			return cmd
		}

		// Mock Fetch
		mockImap.FetchFunc = func(numSet imap.NumSet, options *imap.FetchOptions) *imapclient.FetchCommand {
			// Verify we are fetching all messages (1 to *)
			expectedNumSet := imap.SeqSet{}
			expectedNumSet.AddRange(1,0)
			if !reflect.DeepEqual(numSet, expectedNumSet) {
				t.Errorf("expected Fetch numSet %v, got %v", expectedNumSet, numSet)
			}

			cmd := imapclient.NewFetchCommand(nil)
			go func() {
				// Create a mock message
				msgData := imapclient.NewFetchMessageData(numSet.Nums()[0], options)
				msgData.SetUID(123)
				msgData.SetEnvelope(&imap.Envelope{Subject: "Test Spam"})
				msgData.SetBodySection(0, []byte("This is spam content"))
				cmd.AddMessage(msgData)
				cmd.Close()
			}()
			return cmd
		}

		// Mock Rspamc Spam
		mockRspamc.SpamFunc = func(ctx context.Context, msg io.Reader) error {
			spamFuncCalled = true
			body, _ := io.ReadAll(msg)
			if string(body) != "This is spam content" {
				t.Errorf("expected spam content 'This is spam content', got '%s'", string(body))
			}
			return nil
		}

		// Mock Move
		mockImap.MoveFunc = func(uidSet imap.UIDSet, dest string) *imapclient.MoveCommand {
			movedUIDs = uidSet
			movedToMailbox = dest
			cmd := imapclient.NewMoveCommand(nil, uidSet, dest)
			go func() {
				cmd.Close()
			}()
			return cmd
		}

		client := newTestClient(mockImap, mockRspamc, "LearnSpamSource")
		client.spamMailbox = "TargetSpamFolder" // Set the destination for move

		err := client.ProcessLearnSpam()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if !spamFuncCalled {
			t.Error("Rspamc.Spam was not called")
		}
		
		expectedMovedUIDs := imap.UIDSet{}
		expectedMovedUIDs.AddNum(123)
		if !reflect.DeepEqual(movedUIDs, expectedMovedUIDs) {
			t.Errorf("expected moved UIDs %v, got %v", expectedMovedUIDs, movedUIDs)
		}
		if movedToMailbox != "TargetSpamFolder" {
			t.Errorf("expected moved to 'TargetSpamFolder', got '%s'", movedToMailbox)
		}
	})

	t.Run("rspamc.Spam fails for a message", func(t *testing.T) {
		mockImap := &MockImapClient{}
		mockRspamc := &MockRspamcClient{}
		
		var spamFuncCalled bool
		var moveAttempted bool

		mockImap.SelectFunc = func(mailbox string, options *imap.SelectOptions) *imapclient.SelectCommand {
			cmd := imapclient.NewSelectCommand(nil)
			go func() { cmd.SetData(&imap.SelectData{NumMessages: 1}); cmd.Close() }()
			return cmd
		}
		mockImap.FetchFunc = func(numSet imap.NumSet, options *imap.FetchOptions) *imapclient.FetchCommand {
			cmd := imapclient.NewFetchCommand(nil)
			go func() {
				msgData := imapclient.NewFetchMessageData(1, options)
				msgData.SetUID(123)
				msgData.SetEnvelope(&imap.Envelope{Subject: "Test Spam Fail"})
				msgData.SetBodySection(0, []byte("Spam content that fails"))
				cmd.AddMessage(msgData)
				cmd.Close()
			}()
			return cmd
		}
		mockRspamc.SpamFunc = func(ctx context.Context, msg io.Reader) error {
			spamFuncCalled = true
			return errors.New("rspamc learn failed")
		}
		mockImap.MoveFunc = func(uidSet imap.UIDSet, dest string) *imapclient.MoveCommand {
			moveAttempted = true // Should not be called if SpamFunc failed for all messages
			cmd := imapclient.NewMoveCommand(nil, uidSet, dest)
			go func() { cmd.Close() }()
			return cmd
		}

		client := newTestClient(mockImap, mockRspamc, "LearnSpamFail")
		err := client.ProcessLearnSpam()
		// The current implementation logs the Spam error and continues, so no error is returned by ProcessLearnSpam itself
		// unless the fetch or move operations fail.
		if err != nil {
			t.Fatalf("expected no error from ProcessLearnSpam itself (Spam error is logged), got %v", err)
		}

		if !spamFuncCalled {
			t.Error("Rspamc.Spam was not called")
		}
		if moveAttempted {
			// Because the message was not successfully learned, it should not be in learnedSpamSet,
			// so Move should not be called (or called with an empty set).
			// The current ProcessLearnSpam logic will call Move if learnedSpamSet is not empty.
			// If Spam fails for all, learnedSpamSet will be empty.
			if len(mockImap.MovedUIDSet) > 0 {
				t.Errorf("Move should not have been called with UIDs, but was called with: %v", mockImap.MovedUIDSet)
			}
		}
	})

	t.Run("IMAP move operation fails", func(t *testing.T) {
		mockImap := &MockImapClient{}
		mockRspamc := &MockRspamcClient{}

		mockImap.SelectFunc = func(mailbox string, options *imap.SelectOptions) *imapclient.SelectCommand {
			cmd := imapclient.NewSelectCommand(nil)
			go func() { cmd.SetData(&imap.SelectData{NumMessages: 1}); cmd.Close() }()
			return cmd
		}
		mockImap.FetchFunc = func(numSet imap.NumSet, options *imap.FetchOptions) *imapclient.FetchCommand {
			cmd := imapclient.NewFetchCommand(nil)
			go func() {
				msgData := imapclient.NewFetchMessageData(1, options)
				msgData.SetUID(123)
				msgData.SetEnvelope(&imap.Envelope{Subject: "Test Spam Move Fail"})
				msgData.SetBodySection(0, []byte("Content for move fail"))
				cmd.AddMessage(msgData)
				cmd.Close()
			}()
			return cmd
		}
		mockRspamc.SpamFunc = func(ctx context.Context, msg io.Reader) error {
			return nil // Spam succeeds
		}
		mockImap.MoveFunc = func(uidSet imap.UIDSet, dest string) *imapclient.MoveCommand {
			cmd := imapclient.NewMoveCommand(nil, uidSet, dest)
			go func() {
				cmd.SetError(errors.New("imap move failed"))
				cmd.Close()
			}()
			return cmd
		}

		client := newTestClient(mockImap, mockRspamc, "LearnSpamMoveFail")
		err := client.ProcessLearnSpam()
		
		if err == nil {
			t.Fatal("expected an error from ProcessLearnSpam due to move failure, got nil")
		}
		if !strings.Contains(err.Error(), "moving messages from learnSpamMailbox to spamMailbox") || !strings.Contains(err.Error(), "imap move failed") {
			t.Errorf("expected error to be about move failure, got: %v", err)
		}
	})
}

// Note: Testing loadOrCreateState's interaction with learnSpamMailbox would be
// better done in a separate TestLoadOrCreateState function if not already present.
// This ensures that ProcessLearnSpam tests focus on the processing logic.
// For now, we assume loadOrCreateState is tested elsewhere or correctly initializes
// the necessary state for learnSpamMailbox if it's used by ProcessLearnSpam directly
// (which it isn't for UID tracking like scanMailbox).
// The current ProcessLearnSpam doesn't use UIDLastProcessed for the learnSpamMailbox,
// so state interaction is minimal for this specific method beyond its existence.

func TestLoadOrCreateState(t *testing.T) {
	// Basic test structure for loadOrCreateState if it were to be tested here or expanded
	// This is a placeholder to acknowledge the comment in the subtask.
	// A full test for loadOrCreateState would involve creating/mocking file system operations.

	t.Run("initializes learnSpamMailbox if configured and not in state", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "teststate*.json")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.Close() // Close so os.WriteFile can write to it, or os.ReadFile sees it as empty

		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		c := &Client{
			logger:           logger,
			statefilePath:    tmpFile.Name(),
			scanMailbox:      "Scan",
			hamMailbox:       "Ham",
			learnSpamMailbox: "LearnSpamCustom", // Configured
		}

		// Test 1: File does not exist (or is empty), state should be created
		// Forcing IsNotExist by using a non-existent path temporarily for this part of the test
		// or ensuring the temp file is empty.
		
		// To simulate a truly non-existent file for the IsNotExist branch:
		nonExistentPath := tmpFile.Name() + ".nonexistent"
		c.statefilePath = nonExistentPath

		state, err := c.loadOrCreateState()
		if err != nil {
			t.Fatalf("loadOrCreateState failed for non-existent file: %v", err)
		}
		if _, exists := state.Seen[c.learnSpamMailbox]; !exists {
			t.Errorf("Expected learnSpamMailbox '%s' to be initialized in state when file is new, but it was not", c.learnSpamMailbox)
		}
		if state.Seen[c.learnSpamMailbox] == nil {
			t.Errorf("Expected learnSpamMailbox '%s' to have a non-nil SeenStatus", c.learnSpamMailbox)
		}


		// Test 2: File exists but learnSpamMailbox is not in it
		c.statefilePath = tmpFile.Name() // Revert to the actual temp file
		initialData := `{"seen": {"Scan": {"uid_validity": 1, "uid_last_processed": 10}}}`
		if err := os.WriteFile(tmpFile.Name(), []byte(initialData), 0600); err != nil {
			t.Fatalf("Failed to write initial state: %v", err)
		}

		state, err = c.loadOrCreateState()
		if err != nil {
			t.Fatalf("loadOrCreateState failed: %v", err)
		}
		if _, exists := state.Seen[c.learnSpamMailbox]; !exists {
			t.Errorf("Expected learnSpamMailbox '%s' to be added to state, but it was not", c.learnSpamMailbox)
		}
		if state.Seen[c.learnSpamMailbox] == nil {
			t.Errorf("Expected learnSpamMailbox '%s' to have a non-nil SeenStatus after being added", c.learnSpamMailbox)
		}
		if _, exists := state.Seen["Scan"]; !exists { // Ensure existing data is preserved
			t.Error("Existing 'Scan' mailbox data was lost from state")
		}


		// Test 3: learnSpamMailbox is configured but empty string
		c.learnSpamMailbox = ""
		state, err = c.loadOrCreateState() // Reload with empty learnSpamMailbox
		if err != nil {
			t.Fatalf("loadOrCreateState failed: %v", err)
		}
		if _, exists := state.Seen["LearnSpamCustom"]; exists && c.learnSpamMailbox == "" {
			// This check might be tricky: if "LearnSpamCustom" was added in the previous step, it will still be there.
			// The logic in loadOrCreateState *adds* if learnSpamMailbox is configured AND not present.
			// It doesn't remove entries if learnSpamMailbox config changes from set to unset.
			// This specific test case might need refinement based on desired behavior of loadOrCreateState
			// if a previously configured mailbox is later unconfigured.
			// Current implementation: it just ensures the *currently* configured one is present.
		}
		// A better test for this: ensure it *doesn't* add an empty string key
		if _, exists := state.Seen[""]; exists {
			t.Error("loadOrCreateState should not add an entry for an empty learnSpamMailbox string")
		}
	})
}
