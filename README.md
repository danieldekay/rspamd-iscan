# rspamd-iscan

rspamd-iscan is a daemon that monitors IMAP mailboxes and forwards new mails to 
[rspamd](https://rspamd.com) for spam analysis or ham classification.
It is similar to [isbg](https://gitlab.com/isbg/isbg) but uses rspamd instead of
Spamassassin.


rspamd-iscan scans new mails arriving in a _ScanMailbox_, if they are classified
as Spam they are moved to the _SpamMailbox_, otherwise to the _InboxMailbox_.
The _ScanMailBox_ is monitor via IMAP IDLE for new E-Mails and additionally also
scanned periodically. \
All mails in _HamMailbox_ are fed as Ham to rspamd and then moved to
_InboxMailbox_. The _HamMailbox_ is only processed periodically.

### Detailed Scan Processing and Header Modification

When messages are processed from the `ScanMailbox`:

-   If a message receives a spam score that is greater than 0 but less than the configured `SpamThreshold` (i.e., it's considered ham but did exhibit some spam characteristics):
    -   Rspamd diagnostic headers are added directly into the email's existing headers. These include headers like `X-Spam-Flag`, `X-Rspamd-Score`, `X-Spamd-Bar`, `X-Rspamd-Symbols`, and `X-Rspamd-Action`.
    -   This modified email (with the new headers) is then appended to the `InboxMailbox`.
    -   The original email from the `ScanMailbox` is subsequently deleted.
    -   This feature allows users to see detailed Rspamd processing information directly within emails that were borderline or had some spam characteristics but were ultimately classified as ham.
-   Messages with a spam score of 0 or less are moved to the `InboxMailbox` without any modification or header addition by `rspamd-iscan`.
-   Messages with a spam score equal to or greater than the `SpamThreshold` are moved to the `SpamMailbox`. These messages are not modified with additional headers by `rspamd-iscan` during this process (though Rspamd itself might add headers based on its own configuration for such actions).

The mails that have been scanned last are stored in a state file.

## Configuration

rspamd-iscan can be configured via a TOML configuration file.
Example:

```toml
RspamdURL      = "http://192.168.178.2:11334"
RspamdPassword = "iwonttellyou"
ImapAddr       ="my-imap-server:993"
ImapUser       ="rickdeckard"
ImapPassword   ="zhora"
InboxMailbox   ="INBOX"
SpamMailbox    ="Spam"
HamMailbox     = "Ham"
ScanMailbox    ="Unscanned"
# Optional: Folder from which messages are taken, learned as spam,
# and then moved to SpamMailbox. If not set or empty, this feature is disabled.
LearnSpamMailbox = "LearnSpam"
SpamThreshold = 10.0
```

-   `LearnSpamMailbox`: (Optional) Specifies an IMAP mailbox from which messages are fetched, learned by Rspamd as spam, and then moved to the `SpamMailbox`. If this option is not set or is an empty string, this feature is disabled.

The location of the configuration and state file can be specified via command
line parameters.
