# Command Invariants

## register

- [tested] R-01: register command requires --org and --bot flags; cobra rejects with a usage error if either is not provided.
- [tested] R-02: register resolves the .rtbtr directory without auto-creating it (allowCreate=false); rejects if .rtbtr is not found.
- [tested] R-03: If config.yaml exists with org and bot set and --force is not passed, register rejects with: "already registered as {org}/{bot}, use --force to re-register (warning: re-registering will lose access to all existing messages; this is irrecoverable)".
- [tested] R-04: register rejects with "public key not found, run rtbtr keygen first" if the public_key file is absent from .rtbtr.
- [tested] R-05: register rejects with "org token not found, place your org token in .rtbtr/org_token" if the org_token file is absent from .rtbtr.
- [tested] R-06: register POSTs to {apiBaseURL}/orgs/{org}/bots with Authorization: Bearer {org_token} header and JSON body {"name": bot, "public_key": pubkey}.
- [tested] R-07: When the API returns HTTP 401, register reports "org token is invalid or expired".
- [tested] R-08: When the API returns HTTP 409, register reports "bot already has an active key, revoke it first".
- [tested] R-09: When the API returns HTTP 422 and the response body contains "Public key has already been used", register reports "public key has already been used for this bot, run rtbtr keygen --force to generate a new keypair".
- [tested] R-10: On a successful API response, register writes config.yaml via config.Write with the org and bot values from the command flags.
- [tested] R-11: On success, register prints "registered as {org}/{bot}" and the bot_id from the API response JSON to stdout.
- [tested] R-12: --force flag bypasses the existing-identity check (R-03), allowing re-registration even when config.yaml already contains org and bot.

## inbox

- [tested] I-01: inbox is registered as a subcommand of rootCmd and produces help text when invoked with rtbtr inbox --help.
- [tested] I-02: inbox resolves the .rtbtr directory with allowCreate=false; rejects with an error mentioning ".rtbtr" if the directory is not found.
- [tested] I-03: inbox loads config.yaml from .rtbtr and rejects with "not registered: run rtbtr register first" if org or bot is empty or config.yaml is missing.
- [tested] I-04: inbox reads the private_key file from .rtbtr, trims whitespace, and base64url-no-pad decodes it to obtain the 32-byte Ed25519 seed; rejects with "private key not found" if the file is missing.
- [tested] I-05: inbox sends a GET request to {apiBaseURL}/orgs/{org}/bots/{bot}/inbox with Signature-Input and Signature headers produced by signing.Sign using the decoded seed and "{platformBaseURL}/o/{org}/{bot}" as the key ID.
- [tested] I-06: --direction and --status are optional string flags; when non-empty they are included as query parameters. --page (int, default 1), --limit (int, default 20), and --order (string, default "desc") are always included as query parameters.
- [tested] I-07: --json flag outputs the raw API response body to stdout. When --json is not set, output is a human-readable aligned table (via text/tabwriter) with a header row and one row per message. When the response contains no messages, the table output prints "no messages".
- [tested] I-08: HTTP 401 maps to error "authentication failed: signature rejected"; HTTP 403 maps to "not authorized to access inbox"; other non-2xx responses map to "inbox failed: {status}: {body}".

## send

- [untested] SEND-01: `send` is registered as a root subcommand and `rtbtr send --help` succeeds and mentions `send`.
- [untested] SEND-02: `send` requires `--to` in exact `org/bot` format and rejects missing values, inputs without exactly one `/`, or empty org/bot parts.
- [untested] SEND-03: `send` resolves message content from `--message` or stdin, with `--message` taking priority; if `--message` is absent and stdin is a terminal it rejects with `message required: use --message or pipe to stdin`, and it rejects empty resolved content.
- [untested] SEND-04: `send` resolves the `.rtbtr` directory with `allowCreate=false` and rejects with an error mentioning `.rtbtr` if the directory is missing.
- [untested] SEND-05: `send` loads `config.yaml` from `.rtbtr` and rejects with `not registered: run rtbtr register first` when the configured org or bot is empty.
- [untested] SEND-06: `send` loads `.rtbtr/private_key`, trims whitespace, base64url-no-pad decodes it to the 32-byte Ed25519 seed, and rejects with `private key not found` if the file is absent.
- [untested] SEND-07: Before sending, `send` fetches the recipient profile at `GET {apiBaseURL}/orgs/{org}/bots/{bot}` and maps a 404 response to `recipient not found`.
- [untested] SEND-09: `send` rejects plaintext larger than 1,048,576 bytes before encryption with `message too large (max 1MB)`.
- [untested] SEND-10: `send` POSTs to `{apiBaseURL}/orgs/{recipient_org}/bots/{recipient_bot}/inbox` with a JSON body containing standard-base64 `encrypted_payload` and an `encryption` object with `algorithm`, `recipient_public_key`, and `ephemeral_public_key`.
- [untested] SEND-11: `send` sends mailbox POST requests with `Content-Type: application/json`, a correct `Content-Digest` header, and HTTP signature headers computed over the request body.
- [untested] SEND-12: `send` signs mailbox POST requests with key ID `{platformBaseURL}/o/{sender_org}/{sender_bot}`.
- [untested] SEND-13: On success, `send` prints `sent <message_id>` by default.
- [untested] SEND-14: With `--json`, `send` outputs the raw API response JSON instead of human-friendly text.
- [untested] SEND-15: `send` maps HTTP errors as follows: 401 -> `authentication failed: signature rejected`; 404 -> `recipient not found`; 422 -> `invalid message: {response body}`; other non-2xx -> `send failed: {status}: {body}`.

## read

- [untested] READ-01: `read` is registered as a root subcommand and `rtbtr read --help` succeeds.
- [untested] READ-02: `read` requires a positional `message_id` argument in UUID format and rejects missing or invalid IDs.
- [untested] READ-04: `read` sends a signed `GET {apiBaseURL}/orgs/{org}/bots/{bot}/inbox/{message_id}` using the bot Ed25519 key with a nil body, so Signature headers are present and `Content-Digest` is absent.
- [untested] READ-05: `read` decodes `encrypted_payload` from standard base64, decodes `encryption.ephemeral_public_key` from URL-safe base64, derives the X25519 private key from the Ed25519 seed, decrypts the payload, and emits the plaintext content.
- [untested] READ-06: On decryption failure, `read` prints the decryption error to stderr, still prints the message metadata to stdout, and exits non-zero.
- [untested] READ-07: Default `read` output prints `From:`, `Date:`, and `Status:` headers followed by the decrypted message content as UTF-8, or raw bytes to stdout when the plaintext is not valid UTF-8.
- [untested] READ-08: `read --json` outputs JSON with decrypted `content` replacing `encrypted_payload`; on decryption failure `content` is `null` and `decrypt_error` is added.
- [untested] READ-09: `read` maps HTTP errors as follows: 401 -> `authentication failed: signature rejected`; 403 -> `not authorized to read this message`; 404 -> `message not found`; other non-2xx -> `read failed: {status}: {body}`.

## reply

- [untested] REPLY-01: `reply` is registered as a root subcommand and `rtbtr reply --help` succeeds.
- [untested] REPLY-02: `reply` requires a positional `message_id` argument in UUID format and rejects missing or invalid IDs.
- [untested] REPLY-03: `reply` uses the same message-input rules as `send`: `--message` takes priority over stdin, terminal stdin without `--message` is rejected, and empty resolved content is rejected.
- [untested] REPLY-05: `reply` first reads the original message from `GET {apiBaseURL}/orgs/{org}/bots/{bot}/inbox/{message_id}` using the same signed GET behavior as `read`.
- [untested] REPLY-06: If the original message has `sender.public_key = null`, `reply` rejects with `cannot reply: sender's key has been revoked`.
- [untested] REPLY-07: If the original sender identity is `unknown/unknown`, `reply` rejects with `cannot reply: sender no longer exists`.
- [untested] REPLY-08: `reply` converts the original sender's Ed25519 public key to X25519, encrypts the reply, and POSTs it to `{apiBaseURL}/orgs/{sender_org}/bots/{sender_bot}/inbox` using the same Content-Digest and HTTP-signing behavior as `send`.
- [untested] REPLY-09: On success, `reply` prints `replied to <message_id> -> sent <new_message_id>` by default.
- [untested] REPLY-10: With `--json`, `reply` outputs the raw send API response JSON.
- [untested] REPLY-11: `reply` uses `read` error mappings for the original-message GET step and `send` error mappings for the reply POST step.

