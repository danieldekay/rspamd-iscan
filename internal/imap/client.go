package imap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/fho/rspamd-scan/internal/rspamc"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

const defChanBufSiz = 32

type eventNewMessages struct {
	NewMsgCount uint32
}

type Client struct {
	clt    *imapclient.Client
	logger *slog.Logger

	spamMailbox   string
	hamMailbox    string
	scanMailbox      string
	inboxMailbox     string
	learnSpamMailbox string
	statefilePath    string
	spamTreshold     float32

	hamLearnCheckInterval time.Duration

	eventCh chan eventNewMessages

	rspamc *rspamc.Client
}

func NewClient(
	addr, user, passwd,
	scanMailbox, inboxName, hamMailbox, spamMailboxName, learnSpamMailbox string,
	statefilePath string,
	spamTreshold float32,
	logger *slog.Logger,
	rspamc *rspamc.Client,
) (*Client, error) {
	logger = logger.WithGroup("imap").With("server", addr)
	c := &Client{
		logger:                logger,
		inboxMailbox:          inboxName,
		scanMailbox:           scanMailbox,
		spamMailbox:           spamMailboxName,
		hamMailbox:            hamMailbox,
		learnSpamMailbox:      learnSpamMailbox,
		eventCh:               make(chan eventNewMessages, defChanBufSiz),
		rspamc:                rspamc,
		statefilePath:         statefilePath,
		spamTreshold:          spamTreshold,
		hamLearnCheckInterval: 30 * time.Minute,
	}

	clt, err := imapclient.DialTLS(addr, &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Mailbox: c.mailboxUpdateHandler,
		},
		// DebugWriter: os.Stderr,
	})
	if err != nil {
		return nil, err
	}
	c.clt = clt

	if err := clt.Login(user, passwd).Wait(); err != nil {
		return nil, err
	}

	logger.Debug("connection established", "server", addr)

	return c, nil
}

func (c *Client) mailboxUpdateHandler(d *imapclient.UnilateralDataMailbox) {
	if d.NumMessages == nil {
		c.logger.Debug("ignoring mailbox update with nil NumMessages")
		return
	}

	c.logger.Debug("received mailbox update", "num_messages", *d.NumMessages)
	c.eventCh <- eventNewMessages{NewMsgCount: *d.NumMessages}
}

func (c *Client) Close() error {
	return c.clt.Close()
}

// Monitor monitors mailbox for changes.
// stop must be called before any other imap commands can be processed,
// otherwise the client will hang.
func (c *Client) Monitor(mailbox string) (stop func() error, err error) {
	logger := c.logger.With("mailbox", mailbox)

	logger.Debug("starting to monitor mailbox for changes")
	d, err := c.clt.Select(mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return nil, fmt.Errorf("selecting mailbox %q failed: %w", mailbox, err)
	}

	if d.NumMessages != 0 {
		logger.Debug("mailbox has new message, skipping monitoring", "num_messages", d.NumMessages)
		c.eventCh <- eventNewMessages{NewMsgCount: d.NumMessages}
		return func() error { return nil }, nil
	}

	idlecmd, err := c.clt.Idle()
	if err != nil {
		return nil, err
	}

	return func() error {
		logger.Debug("canceling idle")
		err := errors.Join(idlecmd.Close(), idlecmd.Wait())
		logger.Debug("idle canceled")
		return err
	}, nil
}

type SeenStatus struct {
	UIDValidity      uint32   `json:"uid_validity"`
	UIDLastProcessed imap.UID `json:"uid_last_processed"`
}

type state struct {
	Seen map[string]*SeenStatus `json:"seen"`
}

func (s *state) ToFile(path string) error {
	buf, err := json.Marshal(s)
	if err != nil {
		return err
	}
	err = os.WriteFile(path, buf, 0o640)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) loadOrCreateState() (*state, error) {
	logger := c.logger.With("statefile", c.statefilePath)

	buf, err := os.ReadFile(c.statefilePath)
	if os.IsNotExist(err) {
		logger.Info("state file does not exist, all mails will be scanned")
		return &state{
			Seen: map[string]*SeenStatus{
				c.scanMailbox: {},
				c.hamMailbox:  {},
			},
		}, nil
	}

	var result state
	err = json.Unmarshal(buf, &result)
	if err != nil {
		logger.Error("unmarshaling state file failed, file might be corrupted", "error", err)
		return nil, err
	}
	c.logger.Info("state loaded from file")

	if result.Seen == nil {
		result.Seen = map[string]*SeenStatus{}
	}

	if _, exists := result.Seen[c.hamMailbox]; !exists {
		result.Seen[c.hamMailbox] = &SeenStatus{}
	}

	if _, exists := result.Seen[c.scanMailbox]; !exists {
		result.Seen[c.scanMailbox] = &SeenStatus{}
	}

	if c.learnSpamMailbox != "" {
		if _, exists := result.Seen[c.learnSpamMailbox]; !exists {
			result.Seen[c.learnSpamMailbox] = &SeenStatus{}
		}
	}

	return &result, nil
}

func (c *Client) ProcessHam() error {
	logger := c.logger.With("mailbox.source", c.hamMailbox)

	logger.Debug("checking for new messages")

	mbox, err := c.clt.Select(c.hamMailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return err
	}

	if mbox.NumMessages == 0 {
		logger.Debug("ham mailbox is empty, nothing todo", "event", "imap.mailbox_empty")
		return nil
	}

	logger.Debug("new messages found", "event", "imap.new_messages", "count", mbox.NumMessages)

	n := imap.SeqSet{}
	n.AddRange(1, 0)

	fetchCmd := c.clt.Fetch(n, &imap.FetchOptions{
		Envelope:    true,
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}},
	})
	defer fetchCmd.Close()

	var learnedSet imap.UIDSet
	for {
		msgData := fetchCmd.Next()
		if msgData == nil {
			logger.Debug("msgdata is empty")
			break
		}

		msg, err := msgData.Collect()
		if err != nil {
			return err
		}

		if msg.Envelope == nil {
			return errors.New("msg.Envelope is nil")
		}
		if msg.UID == 0 {
			return errors.New("msg.UID is nil")
		}

		logger := c.logger.With("mail.subject", msg.Envelope.Subject, "mail.uid", msg.UID)
		logger.Debug("fetched message")

		if len(msg.BodySection) != 1 {
			return fmt.Errorf("msg has %d body sections, expecting 1", len(msg.BodySection))
		}
		var txt []byte
		for _, b := range msg.BodySection {
			txt = b
			break
		}
		if txt == nil {
			return errors.New("body is nil")
		}
		if len(txt) == 0 {
			return errors.New("body is empty")
		}

		// TODO: retry Check if it failed with an temporary error
		err = c.rspamc.Ham(context.TODO(), bytes.NewReader(txt))
		if err != nil {
			logger.Info("err", "error", err)
			return nil
		}
		logger.Info("learned ham")
		learnedSet.AddNum(msg.UID)
	}

	err = fetchCmd.Close()
	if err != nil {
		// TODO: try to move the learned messages anyways
		return err
	}

	_, err = c.clt.Move(learnedSet, c.inboxMailbox).Wait()
	if err != nil {
		return fmt.Errorf("moving message to inbox mailbox failed: %w", err)
	}

	logger.Info("moved messages to inbox", "mailbox.destination", c.inboxMailbox)

	return nil
}

func (c *Client) ProcessLearnSpam() error {
	if c.learnSpamMailbox == "" {
		c.logger.Debug("learnSpamMailbox is not configured, skipping")
		return nil
	}
	logger := c.logger.With("mailbox.source", c.learnSpamMailbox)

	logger.Debug("checking for new messages to learn as spam")

	mbox, err := c.clt.Select(c.learnSpamMailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return fmt.Errorf("selecting learnSpamMailbox %q failed: %w", c.learnSpamMailbox, err)
	}

	if mbox.NumMessages == 0 {
		logger.Debug("learnSpamMailbox is empty, nothing todo", "event", "imap.mailbox_empty")
		return nil
	}

	logger.Debug("new messages found", "event", "imap.new_messages", "count", mbox.NumMessages)

	// Fetch all messages in the mailbox.
	// Unlike scanMailbox, we don't need to track UIDLastProcessed for learnSpamMailbox
	// as we process all messages and then move them.
	n := imap.SeqSet{}
	n.AddRange(1, 0) // 0 means all messages from 1 to N.

	fetchCmd := c.clt.Fetch(n, &imap.FetchOptions{
		Envelope:    true,
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}}, // Fetch the entire message body
	})
	defer fetchCmd.Close()

	var learnedSpamSet imap.UIDSet
	for {
		msgData := fetchCmd.Next()
		if msgData == nil {
			logger.Debug("no more messages to fetch from learnSpamMailbox")
			break
		}

		msg, err := msgData.Collect()
		if err != nil {
			// Log error and continue with other messages if possible, or return.
			// For simplicity, returning error for now.
			logger.Error("collecting message data failed", "error", err)
			return fmt.Errorf("collecting message data from learnSpamMailbox failed: %w", err)
		}

		if msg.Envelope == nil {
			logger.Error("msg.Envelope is nil in learnSpamMailbox")
			// Potentially skip this message or return error
			continue // Skip this message
		}
		if msg.UID == 0 {
			logger.Error("msg.UID is 0 in learnSpamMailbox")
			// Potentially skip this message or return error
			continue // Skip this message
		}

		msgLogger := logger.With("mail.subject", msg.Envelope.Subject, "mail.uid", msg.UID)
		msgLogger.Debug("fetched message from learnSpamMailbox")

		if len(msg.BodySection) != 1 {
			msgLogger.Error("message has unexpected number of body sections", "count", len(msg.BodySection))
			continue // Skip this message
		}
		var txt []byte
		for _, b := range msg.BodySection {
			txt = b
			break
		}
		if txt == nil {
			msgLogger.Error("message body is nil")
			continue
		}
		if len(txt) == 0 {
			msgLogger.Error("message body is empty")
			continue
		}

		err = c.rspamc.Spam(context.TODO(), bytes.NewReader(txt))
		if err != nil {
			// Log the error but continue processing other messages.
			// We don't want one failed learn attempt to stop others.
			msgLogger.Error("failed to learn message as spam", "error", err)
			// Optionally, decide if certain errors are fatal and should return.
			// For now, just log and continue.
		} else {
			msgLogger.Info("learned message as spam successfully")
			learnedSpamSet.AddNum(msg.UID)
		}
	}

	if err := fetchCmd.Close(); err != nil {
		logger.Error("fetch command for learnSpamMailbox failed on close", "error", err)
		// Decide if we should attempt to move already processed messages or return.
		// Returning the error for now.
		return fmt.Errorf("fetch command for learnSpamMailbox failed: %w", err)
	}

	if len(learnedSpamSet) > 0 {
		// Move successfully learned messages to the main spam mailbox
		_, err = c.clt.Move(learnedSpamSet, c.spamMailbox).Wait()
		if err != nil {
			return fmt.Errorf("moving messages from learnSpamMailbox to spamMailbox %q failed: %w", c.spamMailbox, err)
		}
		logger.Info("moved learned spam messages to spam mailbox", "mailbox.destination", c.spamMailbox, "count", len(learnedSpamSet))
	} else {
		logger.Debug("no messages were learned as spam or moved from learnSpamMailbox")
	}

	return nil
}

func (c *Client) ProcessScanBox(startStatus *SeenStatus) (*SeenStatus, error) {
	status := *startStatus

	logger := c.logger.With("mailbox.source", c.scanMailbox)

	mbox, err := c.clt.Select(c.scanMailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return startStatus, err
	}

	if mbox.UIDValidity != startStatus.UIDValidity {
		logger.Info("uidValidity of mailbox changed, reseting last seen UID, scanning all messages",
			"uid_validity_last", startStatus.UIDValidity, "uid_validity_new", mbox.UIDValidity,
			"event", "imap.uidvalidity_change",
		)
		status.UIDValidity = mbox.UIDValidity
		status.UIDLastProcessed = 0
	}

	if mbox.NumMessages == 0 {
		logger.Info("scan mailbox is empty, nothing to do", "event", "imap.mailbox_empty")
		return &status, nil
	}

	if mbox.UIDNext == startStatus.UIDLastProcessed+1 {
		logger.Debug("all messages have already been processed, nothing to do",
			"event", "imap.mailbox_all_scanned",
			"last_seen.uid_validity", startStatus.UIDValidity,
			"last_seen.processed", startStatus.UIDLastProcessed,
			"mailbox_update.uid_validity", mbox.UIDValidity,
			"mailbox_update.uid_next", mbox.UIDNext,
		)
		return &status, nil
	}

	numSet := imap.UIDSet{}
	numSet.AddRange(status.UIDLastProcessed+1, 0)

	fetchCmd := c.clt.Fetch(numSet, &imap.FetchOptions{
		Envelope: true,
		BodySection: []*imap.FetchItemBodySection{
			{},
		},
	})
	defer fetchCmd.Close()

	inboxSeqSet := imap.UIDSet{}
	spamSeqSet := imap.UIDSet{}

	var errs []error
	for {
		msgData := fetchCmd.Next()
		if msgData == nil {
			break
		}

		msg, err := msgData.Collect()
		if err != nil {
			return &status, err
		}
		if msg.Envelope == nil {
			return startStatus, errors.New("msg.Envelope is nil")
		}

		if msg.UID == 0 {
			return startStatus, errors.New("msg UID is nil")
		}

		logger := c.logger.With("mail.subject", msg.Envelope.Subject, "mail.uid", msg.UID)
		logger.Debug("fetched message")

		if len(msg.BodySection) != 1 {
			return startStatus, fmt.Errorf("msg has %d body sections, expecting 1", len(msg.BodySection))
		}
		var txt []byte
		for _, b := range msg.BodySection {
			txt = b
			break
		}
		if txt == nil {
			return startStatus, errors.New("body is nil")
		}
		if len(txt) == 0 {
			return startStatus, errors.New("body is empty")
		}

		// TODO: retry Check if it failed with an temporary error
		scanResult, err := c.rspamc.Check(context.Background(), bytes.NewReader(txt))
		if err != nil {
			// TODO: if an error happens, try to move the ones that
			// we already scanned
			return startStatus, err
		}
		logger = logger.With("scan.result", scanResult.Action, "scan.score", scanResult.Score, "scan.skipped", scanResult.IsSkipped)
		logger.Debug("message scanned", "scan.symbols", scanResult.Symbols)

		switch v := scanResult.Score; {
		case v >= c.spamTreshold:
			spamSeqSet.AddNum(msg.UID)
		default:
			inboxSeqSet.AddNum(msg.UID)
		}

		if msg.UID > status.UIDLastProcessed {
			status.UIDLastProcessed = msg.UID
		}
	}

	err = fetchCmd.Close()
	if err != nil {
		return startStatus, err
	}

	if len(inboxSeqSet) > 0 {
		_, err = c.clt.Move(inboxSeqSet, c.inboxMailbox).Wait()
		if err != nil {
			errs = append(errs, fmt.Errorf("moving message to inbox mailbox failed: %w", err))
		} else {
			logger.Info("moved messages to inbox", "mailbox.destination", c.inboxMailbox)
		}
	}

	if len(spamSeqSet) > 0 {
		_, err = c.clt.Move(spamSeqSet, c.spamMailbox).Wait()
		if err != nil {
			errs = append(errs, fmt.Errorf("moving message to spam mailbox failed: %w", err))
		} else {
			logger.Info("moved messages to spam mailbox", "mailbox.spam", c.spamMailbox)
		}
	}

	if err := errors.Join(errs...); err != nil {
		// we did not keep track of which mails were processed
		// successfully and which wasn't, return startStatus to ensure
		// the failed ones are processed again
		return startStatus, err
	}

	return &status, nil
}

func (c *Client) writeStateFile(s *state) error {
	err := s.ToFile(c.statefilePath)
	if err != nil {
		return err
	}
	c.logger.Info("wrote state to file", "statefile", c.statefilePath)
	return nil
}

func (c *Client) Run() error {
	lastSeen, err := c.loadOrCreateState()
	if err != nil {
		return err
	}

	err = c.ProcessHam()
	if err != nil {
		return fmt.Errorf("learning ham failed: %w", err)
	}

	err = c.ProcessLearnSpam()
	if err != nil {
		return fmt.Errorf("learning spam failed: %w", err)
	}

	seen, err := c.ProcessScanBox(lastSeen.Seen[c.scanMailbox])
	lastSeen.Seen[c.scanMailbox] = seen
	if err := c.writeStateFile(lastSeen); err != nil {
		return fmt.Errorf("writing state file failed: %w", err)
	}
	if err != nil {
		return err
	}

	monitorCancelFn, err := c.Monitor(c.scanMailbox)
	if err != nil {
		return WrapRetryableError(err)
	}

	c.logger.Debug("waiting for mailbox update events")

	var lastHamLearn time.Time
	for {
		select {
		// sometimes monitoring stops working and no updates are
		// send anymore, despite new imap messages,
		// therefore we additionally check every 30min for new
		// mails, to workaround it.
		case <-time.After(30 * time.Minute):
			c.logger.Debug("timer expired, checking mailbox for new messages")

			if err := monitorCancelFn(); err != nil {
				return WrapRetryableError(err)
			}
			seen, err := c.ProcessScanBox(lastSeen.Seen[c.scanMailbox])
			lastSeen.Seen[c.scanMailbox] = seen
			// TODO: ProcessScanBox returns early, and returns
			// lastSeen if there is nothing to do, do not write the
			// file unnecessarily.
			if err := c.writeStateFile(lastSeen); err != nil {
				return fmt.Errorf("writing state file failed: %w", err)
			}
			if err != nil {
				return err
			}

			if time.Since(lastHamLearn) >= c.hamLearnCheckInterval {
				if err := c.ProcessHam(); err != nil {
					return err
				}
				if err := c.ProcessLearnSpam(); err != nil {
					// Log or handle as appropriate, maybe not fatal
					c.logger.Error("processing learn spam mailbox failed during periodic check", "error", err)
				}
				lastHamLearn = time.Now()
			}

			monitorCancelFn, err = c.Monitor(c.scanMailbox)
			if err != nil {
				return WrapRetryableError(err)
			}

		case evA, ok := <-c.eventCh:
			if !ok {
				c.logger.Debug("event channel was closed")
				_ = monitorCancelFn()
				return nil
			}

			if err := monitorCancelFn(); err != nil {
				return WrapRetryableError(err)
			}

			if time.Since(lastHamLearn) >= c.hamLearnCheckInterval {
				if err := c.ProcessHam(); err != nil {
					return err
				}
				if err := c.ProcessLearnSpam(); err != nil {
					// Log or handle as appropriate
					c.logger.Error("processing learn spam mailbox failed after event", "error", err)
				}
				lastHamLearn = time.Now()
			}

			// TODO: we might receive multiple events at once,
			// instead of processing all sequentially, fetch
			// all and only call ProcessScanBox 1x
			if evA.NewMsgCount == 0 {
				c.logger.Info("ignoring MailboxUpdate, no new messages")
				continue
			}

			seen, err := c.ProcessScanBox(lastSeen.Seen[c.scanMailbox])
			lastSeen.Seen[c.scanMailbox] = seen
			// TODO: ProcessScanBox returns early, and returns
			// lastSeen if there is nothing to do, do not write the
			// file unnecessarily.
			if err := c.writeStateFile(lastSeen); err != nil {
				return fmt.Errorf("writing state file failed: %w", err)
			}
			if err != nil {
				return err
			}

			monitorCancelFn, err = c.Monitor(c.scanMailbox)
			if err != nil {
				return WrapRetryableError(err)
			}
		}
	}
}
