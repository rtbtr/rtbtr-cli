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
