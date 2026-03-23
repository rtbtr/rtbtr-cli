# Config Invariants

- [untested] C-01: config.Load reads config.yaml from a .rtbtr directory and returns the org and bot fields; returns a non-nil error if the file is absent or malformed.
- [untested] C-02: config.Write writes a config.yaml file to a .rtbtr directory containing the org and bot fields in YAML format; creates or overwrites the file with mode 0644.
