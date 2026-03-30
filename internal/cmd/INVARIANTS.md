# Command Invariants

## root

- [tested] ROOT-01: `rtbtr --help` produces non-empty output describing the CLI.
- [tested] ROOT-02: `rtbtr version` subcommand prints version information and exits successfully.
- [tested] ROOT-03: `rootCmd.SilenceUsage` and `rootCmd.SilenceErrors` are both true — cobra does not auto-print usage or error text.
- [tested] ROOT-04: `--home` is a persistent flag available to all subcommands, overriding the default .rtbtr directory resolution.
- [tested] ROOT-05: `Execute()` runs a non-blocking background update check via `selfupdate.CheckForUpdate`; the nudge is printed to stderr only on success, not after `upgrade`, and only when the check completes before the command finishes. Dev builds skip the update check entirely.

## version

- [tested] VER-01: `rtbtr version` prints "rtbtr {version} (commit: {commit}, built: {buildtime})" to stdout using `version.Info()`.

## keygen

- [tested] KG-01: `keygen` is registered as a root subcommand and `rtbtr keygen --help` succeeds and mentions "keygen" and "Ed25519".
- [tested] KG-02: `keygen` resolves the .rtbtr directory with `allowCreate=true`, creating it if it does not exist.
- [tested] KG-03: `keygen` generates an Ed25519 keypair and writes the 32-byte seed to `private_key` and the 32-byte public key to `public_key` in the .rtbtr directory, both as URL-safe base64 with no padding.
- [tested] KG-04: Both `private_key` and `public_key` files are written with mode 0600.
- [tested] KG-05: The stored public key can be derived from the stored private key seed, proving they form a valid Ed25519 pair.
- [tested] KG-06: `keygen` prints the public key (URL-safe base64, no padding) to stdout.
- [tested] KG-07: Without `--force`, `keygen` refuses to overwrite an existing `private_key` or `public_key` file and reports "private key already exists" or "public key already exists" with the file path. Existing files are not modified.
- [tested] KG-08: With `--force`, `keygen` overwrites existing key files with a new valid keypair.
- [tested] KG-09: When the .rtbtr directory is inside a git repository (a `.git` directory exists in any ancestor), `keygen` prints a warning to stderr advising the user to add `private_key` to `.gitignore`.
- [tested] KG-10: When the .rtbtr directory is NOT inside a git repository, `keygen` produces no stderr output.

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
- [tested] R-13: register validates --org and --bot against `^[a-zA-Z0-9_-]+$`; rejects with "invalid org" or "invalid bot" for values containing spaces, slashes, or other special characters.
- [tested] R-14: Non-2xx responses not covered by specific mappings (e.g. 500) produce a generic "register failed: {status}: {body}" error.

## inbox

- [tested] I-01: inbox is registered as a subcommand of rootCmd and produces help text when invoked with rtbtr inbox --help.
- [tested] I-02: inbox resolves the .rtbtr directory with allowCreate=false; rejects with an error mentioning ".rtbtr" if the directory is not found.
- [tested] I-03: inbox loads config.yaml from .rtbtr and rejects with "not registered: run rtbtr register first" if org or bot is empty or config.yaml is missing.
- [tested] I-04: inbox reads the private_key file from .rtbtr, trims whitespace, and base64url-no-pad decodes it to obtain the 32-byte Ed25519 seed; rejects with "private key not found" if the file is missing.
- [tested] I-05: inbox sends a GET request to {apiBaseURL}/orgs/{org}/bots/{bot}/inbox with Signature-Input and Signature headers produced by signing.Sign using the decoded seed and "{platformBaseURL}/o/{org}/{bot}" as the key ID.
- [tested] I-06: --direction is an optional string flag; when non-empty it is included as a query parameter. --status (string, default "all"), --page (int, default 1), --limit (int, default 20), and --order (string, default "desc") are always included as query parameters.
- [tested] I-07: --json flag outputs the raw API response body to stdout. When --json is not set, output is a human-readable aligned table (via text/tabwriter) with a header row and one row per message. When the response contains no messages, the table output prints "no messages".
- [tested] I-08: HTTP 401 maps to error "authentication failed: signature rejected"; HTTP 403 maps to "not authorized to access inbox"; other non-2xx responses map to "inbox failed: {status}: {body}".

## send

- [tested] SEND-01: `send` is registered as a root subcommand and `rtbtr send --help` succeeds and mentions `send`.
- [tested] SEND-02: `send` requires `--to` in exact `org/bot` format and rejects missing values, inputs without exactly one `/`, or empty org/bot parts.
- [tested] SEND-03: `send` resolves message content from `--message` or stdin, with `--message` taking priority; if `--message` is absent and stdin is a terminal it rejects with `message required: use --message or pipe to stdin`, and it rejects empty resolved content.
- [tested] SEND-04: `send` resolves the `.rtbtr` directory with `allowCreate=false` and rejects with an error mentioning `.rtbtr` if the directory is missing.
- [tested] SEND-05: `send` loads `config.yaml` from `.rtbtr` and rejects with `not registered: run rtbtr register first` when the configured org or bot is empty.
- [tested] SEND-06: `send` loads `.rtbtr/private_key`, trims whitespace, base64url-no-pad decodes it to the 32-byte Ed25519 seed, and rejects with `private key not found` if the file is absent.
- [tested] SEND-07: Before sending, `send` fetches the recipient profile at `GET {apiBaseURL}/orgs/{org}/bots/{bot}` and maps a 404 response to `recipient not found`.
- [tested] SEND-09: `send` rejects plaintext larger than 1,048,576 bytes before encryption with `message too large (max 1MB)`.
- [tested] SEND-10: `send` POSTs to `{apiBaseURL}/orgs/{recipient_org}/bots/{recipient_bot}/inbox` with a JSON body containing standard-base64 `encrypted_payload` and an `encryption` object with `algorithm`, `recipient_public_key`, and `ephemeral_public_key`.
- [tested] SEND-11: `send` sends mailbox POST requests with `Content-Type: application/json`, a correct `Content-Digest` header, and HTTP signature headers computed over the request body.
- [tested] SEND-12: `send` signs mailbox POST requests with key ID `{platformBaseURL}/o/{sender_org}/{sender_bot}`.
- [tested] SEND-13: On success, `send` prints `sent <message_id>` by default.
- [tested] SEND-14: With `--json`, `send` outputs the raw API response JSON instead of human-friendly text.
- [tested] SEND-15: `send` maps HTTP errors as follows: 401 -> `authentication failed: signature rejected`; 404 -> `recipient not found`; 422 -> `invalid message: {response body}`; other non-2xx -> `send failed: {status}: {body}`.

## read

- [tested] READ-01: `read` is registered as a root subcommand and `rtbtr read --help` succeeds.
- [tested] READ-02: `read` requires a positional `message_id` argument in UUID format and rejects missing or invalid IDs.
- [tested] READ-04: `read` sends a signed `GET {apiBaseURL}/orgs/{org}/bots/{bot}/inbox/{message_id}` using the bot Ed25519 key with a nil body, so Signature headers are present and `Content-Digest` is absent.
- [tested] READ-05: `read` decodes `encrypted_payload` from standard base64, decodes `encryption.ephemeral_public_key` from URL-safe base64, derives the X25519 private key from the Ed25519 seed, decrypts the payload, and emits the plaintext content.
- [tested] READ-06: On decryption failure, `read` prints the decryption error to stderr, still prints the message metadata to stdout, and exits non-zero.
- [tested] READ-07: Default `read` output prints `From:`, `Date:`, and `Status:` headers followed by the decrypted message content as UTF-8, or raw bytes to stdout when the plaintext is not valid UTF-8.
- [tested] READ-08: `read --json` outputs JSON with decrypted `content` replacing `encrypted_payload`; on decryption failure `content` is `null` and `decrypt_error` is added.
- [tested] READ-09: `read` maps HTTP errors as follows: 401 -> `authentication failed: signature rejected`; 403 -> `not authorized to read this message`; 404 -> `message not found`; other non-2xx -> `read failed: {status}: {body}`.

## reply

- [tested] REPLY-01: `reply` is registered as a root subcommand and `rtbtr reply --help` succeeds.
- [tested] REPLY-02: `reply` requires a positional `message_id` argument in UUID format and rejects missing or invalid IDs.
- [tested] REPLY-03: `reply` uses the same message-input rules as `send`: `--message` takes priority over stdin, terminal stdin without `--message` is rejected, and empty resolved content is rejected.
- [tested] REPLY-05: `reply` first reads the original message from `GET {apiBaseURL}/orgs/{org}/bots/{bot}/inbox/{message_id}` using the same signed GET behavior as `read`.
- [tested] REPLY-06: If the original message has `sender.public_key = null`, `reply` rejects with `cannot reply: sender's key has been revoked`.
- [tested] REPLY-07: If the original sender identity is `unknown/unknown`, `reply` rejects with `cannot reply: sender no longer exists`.
- [tested] REPLY-08: `reply` converts the original sender's Ed25519 public key to X25519, encrypts the reply, and POSTs it to `{apiBaseURL}/orgs/{sender_org}/bots/{sender_bot}/inbox` using the same Content-Digest and HTTP-signing behavior as `send`.
- [tested] REPLY-09: On success, `reply` prints `replied to <message_id> -> sent <new_message_id>` by default.
- [tested] REPLY-10: With `--json`, `reply` outputs the raw send API response JSON.
- [tested] REPLY-11: `reply` uses `read` error mappings for the original-message GET step and `send` error mappings for the reply POST step.

## whoami

- [tested] W-01: `whoami` is registered as a root subcommand.
- [tested] W-02: `whoami` resolves the .rtbtr directory with `allowCreate=false`; rejects with an error mentioning ".rtbtr" if the directory is not found.
- [tested] W-03: `whoami` loads config.yaml and rejects with "not registered: run rtbtr register first" if org or bot is empty, or with an error mentioning "config" if config.yaml is missing.
- [tested] W-04: `whoami` reads the `public_key` file from .rtbtr, trims whitespace, and rejects with an error mentioning "public key" if the file is missing.
- [tested] W-05: Default output prints labeled fields `Org:`, `Bot:`, and `Public Key:` with the corresponding values.
- [tested] W-06: `--json` flag outputs a JSON object with keys `org`, `bot`, and `public_key` in that order.
- [tested] W-07: `whoami` never exposes the private_key or org_token contents in its output.
- [tested] W-08: `whoami` respects the `--home` flag to locate the .rtbtr directory.
- [tested] W-09: `whoami` is fully offline — it makes no network requests.

## lookup

- [tested] L-01: `lookup` is registered as a root subcommand and `rtbtr lookup --help` succeeds.
- [tested] L-02: `lookup` requires exactly one positional argument; rejects when missing or when extra arguments are given.
- [tested] L-03: `lookup` validates the positional argument as `org/bot` format; rejects input without a slash, with multiple slashes, or with empty org/bot parts with an error mentioning "org/bot".
- [tested] L-04: `lookup` sends an unauthenticated `GET {apiBaseURL}/orgs/{org}/bots/{bot}` — no Authorization, Signature-Input, or Signature headers are sent. It does not require the .rtbtr directory or any local identity.
- [tested] L-05: Default output displays labeled fields: `Org:`, `Bot:`, `Public Key:`, optionally `Description:` (only if non-empty), and `Created:`.
- [tested] L-06: `--json` flag outputs the raw API response body to stdout, preserving all fields including unknown/extra ones.
- [tested] L-07: HTTP 404 maps to "bot not found".
- [tested] L-08: Non-2xx responses (other than 404) map to "lookup failed: {status}: {body}".

## sign

- [tested] SIGN-01: `sign` is registered as a root subcommand with `Args: cobra.NoArgs`.
- [tested] SIGN-02: `sign` resolves the .rtbtr directory with `allowCreate=false` and loads the private key via `home.LoadPrivateKey`; rejects with "private key not found" if the file is absent.
- [tested] SIGN-03: `sign` reads all of stdin (max 1MB), rejects empty input with "empty input", and rejects input exceeding 1MB with "input too large (max 1MB)".
- [tested] SIGN-04: `sign` produces a 64-byte Ed25519 signature encoded as standard base64 with padding (88 characters ending with "==") on a single stdout line with no trailing whitespace.
- [tested] SIGN-05: The signature output uses standard base64 alphabet (`+`, `/`, `=`) — never URL-safe characters (`-`, `_`).
- [tested] SIGN-06: The signature produced by `sign` is verifiable with `ed25519.Verify` using the corresponding public key.
- [tested] SIGN-07: `sign` rejects malformed private key files (valid base64 but wrong decoded length) with an error mentioning "private key" — no panic.
- [tested] SIGN-08: The sign output is RFC 8941 byte-sequence compatible — it can be wrapped in `:<base64>:` delimiters and decoded as a Structured Fields byte sequence.

## verify

- [tested] V-01: `verify` is registered as a root subcommand with `Args: cobra.NoArgs`.
- [tested] V-02: `verify` requires `--key` (org/bot format) and `--signature` (standard base64) flags; cobra rejects if either is missing.
- [tested] V-03: `verify` fetches the signer's Ed25519 public key from the API via `FetchRecipientKey`; maps a 404 response to "signer {org}/{bot} not found".
- [tested] V-04: `verify` decodes `--signature` from standard base64 and rejects invalid base64 or wrong-length signatures (not 64 bytes) with "invalid signature length".
- [tested] V-05: `verify` reads all of stdin (max 1MB), rejects empty input with "empty input", and rejects input exceeding 1MB with "input too large (max 1MB)".
- [tested] V-06: On valid signature, `verify` prints "valid" to stdout and returns nil (exit 0).
- [tested] V-07: On invalid signature, `verify` prints "invalid" to stdout and returns `ErrInvalidSignature` (exit 1).
- [tested] V-08: `verify` rejects `--key` values not in org/bot format.
- [tested] V-09: A sign->verify roundtrip succeeds: the output of `rtbtr sign` can be passed directly to `rtbtr verify --signature` without re-encoding.

## encrypt

- [tested] ENC-01: `encrypt` is registered as a root subcommand with `Args: cobra.NoArgs` and `rtbtr encrypt --help` succeeds.
- [tested] ENC-02: `encrypt` requires `--to` flag in `org/bot` format; cobra rejects if missing, and the command rejects malformed values.
- [tested] ENC-03: `encrypt` resolves message content from `--message` or stdin using the same rules as `send`: `--message` takes priority, terminal stdin without `--message` is rejected, empty/whitespace-only content is rejected.
- [tested] ENC-04: `encrypt` rejects messages larger than 1MB with "message too large (max 1MB)"; accepts messages at exactly 1MB.
- [tested] ENC-05: `encrypt` fetches the recipient's Ed25519 public key from the API, converts it to X25519, and encrypts using X25519 ECDH + AES-256-GCM. Maps 404 to "recipient {org}/{bot} not found".
- [tested] ENC-06: `encrypt` outputs a JSON envelope to stdout with three fields: `ciphertext` (standard base64), `ephemeral_public_key` (URL-safe base64, no padding, 32 bytes decoded), and `algorithm` ("x25519-aes256gcm").
- [tested] ENC-07: Encryption is non-deterministic — encrypting the same message twice produces different output.
- [tested] ENC-08: `encrypt` does not accept positional arguments.
- [tested] ENC-09: An encrypt->decrypt CLI roundtrip recovers the original plaintext, both via `--message`/`--payload` flags and via stdin piping.

## decrypt

- [tested] DEC-01: `decrypt` is registered as a root subcommand with `Args: cobra.NoArgs` and `rtbtr decrypt --help` succeeds.
- [tested] DEC-02: `decrypt` accepts the JSON envelope via `--payload` flag or piped stdin; rejects terminal stdin without `--payload` with "payload required: use --payload or pipe to stdin"; rejects empty payload.
- [tested] DEC-03: `decrypt` validates the JSON envelope and rejects invalid JSON, missing `ciphertext` field, or missing `ephemeral_public_key` field.
- [tested] DEC-04: `decrypt` resolves the .rtbtr directory with `allowCreate=false`; rejects with an error mentioning ".rtbtr" if the directory is not found.
- [tested] DEC-05: `decrypt` loads the private key via `home.LoadPrivateKey`; rejects with "private key not found" if the file is missing.
- [tested] DEC-06: `decrypt` derives the X25519 private key from the Ed25519 seed, decodes ciphertext from standard base64 and ephemeral_public_key from URL-safe base64, and decrypts using AES-256-GCM.
- [tested] DEC-07: `decrypt` writes raw plaintext bytes to stdout with no trailing newline — suitable for piping. Stderr is empty on success.
- [tested] DEC-08: `decrypt` with the wrong private key returns a decryption error (not a panic).
- [tested] DEC-09: `decrypt` rejects tampered ciphertext (AEAD authentication failure).
- [tested] DEC-10: `decrypt` handles large payloads (near 1MB) and binary/unicode content correctly.
- [tested] DEC-11: `decrypt` does not accept positional arguments.

## upgrade

- [tested] UPG-01: `upgrade` is registered as a root subcommand and `rtbtr upgrade --help` succeeds.
- [tested] UPG-02: `upgrade` rejects dev builds with "cannot upgrade a dev build" when `version.Version == "dev"`.
- [tested] UPG-03: When `DetectUpgrade` returns nil (already up to date), `upgrade` prints "rtbtr is already up to date ({version})".
- [tested] UPG-04: When `DetectUpgrade` returns an error, `upgrade` reports it as "check for updates: {error}".
- [tested] UPG-05: When `ApplyUpgrade` returns an error, `upgrade` reports it as "upgrade failed: {error}".
- [tested] UPG-06: On successful upgrade, `upgrade` prints "Updated rtbtr {old_version} → {new_version}".

## profile

- [tested] P-01: `profile` is registered as a root subcommand with `Args: cobra.NoArgs` and `rtbtr profile --help` succeeds.
- [tested] P-02: `profile` requires at least one of `--name` or `--description`; rejects with "at least one of --name or --description is required" when neither is provided.
- [tested] P-03: `profile` resolves the .rtbtr directory with `allowCreate=false`; rejects with an error mentioning ".rtbtr" if the directory is not found.
- [tested] P-04: `profile` loads config.yaml and rejects with "not registered: run rtbtr register first" if org or bot is empty or config.yaml is missing.
- [tested] P-05: `profile` loads the private key via `home.LoadPrivateKey`; rejects with "private key not found" if the file is missing.
- [tested] P-06: `--description` only sends a PATCH to `{apiBaseURL}/orgs/{org}/bots/{bot}` with a JSON body containing only the `description` field (no `name`). An explicit empty string `--description ""` sends `"description":""` in the body so existing descriptions can be cleared.
- [tested] P-07: `--name` without `--force` is rejected with "changing bot name is irreversible; use --force to confirm".
- [tested] P-08: `--name` with `--force` sends a PATCH with the `name` field in the JSON body.
- [tested] P-09: Both `--name` and `--description` together send a PATCH with both fields in the body.
- [tested] P-10: `--description` is limited to 500 characters (Unicode runes, not bytes); rejects with "description must be 500 characters or fewer (got {count})" when exceeded. Exactly 500 runes is accepted. Multi-byte characters are counted as single characters.
- [tested] P-11: `--name` must be at least 2 characters and match `^[a-z0-9][a-z0-9-]*[a-z0-9]$` (lowercase alphanumeric and hyphens, cannot start or end with hyphen); rejects with descriptive errors for violations.
- [tested] P-12: PATCH requests include `Signature-Input` and `Signature` headers, with `keyid="{platformBaseURL}/o/{org}/{bot}"`.
- [tested] P-13: PATCH body is covered by `Content-Digest: sha-256=:....:` and `"content-digest"` is included in the signed components.
- [tested] P-14: PATCH requests include `Content-Type: application/json`.
- [tested] P-15: HTTP 401 maps to "authentication failed: signature rejected".
- [tested] P-16: HTTP 403 maps to "cannot update another bot".
- [tested] P-17: HTTP 404 maps to "bot not found".
- [tested] P-18: HTTP 409 maps to "name conflict: name is already taken".
- [tested] P-19: HTTP 422 maps to "validation error: {response body}".
- [tested] P-20: Non-2xx responses not otherwise mapped (e.g. 500) produce "profile failed: {status}: {body}".
- [tested] P-21: After a successful `--name --force` rename, local config.yaml is updated with the server-confirmed new bot name (preserving org). After a failed rename (non-2xx), config.yaml is not modified. A description-only update does not change config.yaml.

## claim

- [untested] CL-01: `claim` is registered as a root subcommand with `Args: cobra.NoArgs`.
- [untested] CL-02: `claim` resolves the `.rtbtr` directory with `allowCreate=false`; rejects with error mentioning `.rtbtr` if not found.
- [untested] CL-03: `claim` loads `config.yaml` and rejects with `"not registered: run rtbtr register first"` if org or bot is empty or config is missing.
- [untested] CL-04: `claim` loads the private key via `home.LoadPrivateKey`; rejects with `"private key not found"` if missing.
- [untested] CL-05: `--file <path>` reads the file streaming through SHA-256 (constant memory via `io.Copy`), encodes as URL-safe base64 (no padding, 43 chars). Empty files allowed.
- [untested] CL-06: `--stdin` reads stdin streaming through SHA-256. Rejects empty stdin (0 bytes).
- [untested] CL-07: `--hash <value>` validates before sending: exactly 43 chars, URL-safe base64 alphabet, decodes to exactly 32 bytes.
- [untested] CL-08: Exactly one of `--file`, `--stdin`, or `--hash` must be provided.
- [untested] CL-09: POSTs to `{apiBaseURL}/orgs/{org}/bots/{bot}/claims` with `Content-Type: application/json` and body `{"hash": "<43-char URL-safe base64>"}` where org/bot come from local config.
- [untested] CL-10: POST includes `Content-Digest` and HTTP signature headers with `keyid="{platformBaseURL}/o/{org}/{bot}"` and `alg="ed25519"`.
- [untested] CL-11: Default output prints `"claimed <claim_id>"` on line 1 and `"hash: <hash>"` on line 2.
- [untested] CL-12: `--json` outputs the raw API response body to stdout.
- [untested] CL-13: HTTP error mapping: 401, 404, 422, other non-2xx.

## claims

- [untested] CLS-01: `claims` is registered as a root subcommand.
- [untested] CLS-02: `claims` requires exactly one positional argument in `org/bot` format.
- [untested] CLS-03: `claims` sends an unauthenticated GET. No `.rtbtr` directory or local identity required.
- [untested] CLS-04: `--page`, `--limit`, and `--order` always included as query parameters. No client-side validation.
- [untested] CLS-05: Table output via `text/tabwriter` with `ID HASH CREATED` header. Empty result prints `"no claims"`. `--json` outputs raw response.
- [untested] CLS-06: HTTP error mapping: 404, 422, other non-2xx.
