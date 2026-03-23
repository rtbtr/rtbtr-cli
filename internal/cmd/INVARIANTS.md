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
