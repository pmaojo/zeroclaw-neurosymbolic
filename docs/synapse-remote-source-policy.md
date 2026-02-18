# Synapse Remote Source Policy (Deny by Default)

ZeroClaw now enforces **deny-by-default** controls for remote Synapse scenario content in runtime-facing paths.

## What changed

New configuration keys under `[memory.synapse_source_policy]`:

```toml
[memory.synapse_source_policy]
allow_remote_scenarios = false
allowed_registry_hosts = []
max_download_size_bytes = 5242880
```

- `allow_remote_scenarios` controls whether any remote scenario/registry download is allowed.
- `allowed_registry_hosts` is an explicit host allowlist for remote registry/scenario URLs.
- `max_download_size_bytes` caps each downloaded remote artifact (manifest/data/schema/docs).

## New defaults

- Remote scenario loading is disabled by default.
- Empty host allowlist means no remote hosts are trusted.
- Max download size defaults to 5 MiB.

## Migration guidance

If you rely on remote Synapse scenario installation, explicitly opt in:

1. Set `allow_remote_scenarios = true`.
2. Add each trusted remote host to `allowed_registry_hosts`.
3. Keep `max_download_size_bytes` constrained to the smallest practical value.

Example:

```toml
[memory]
backend = "synapse"

[memory.synapse_source_policy]
allow_remote_scenarios = true
allowed_registry_hosts = ["raw.githubusercontent.com", "synapse.example.com"]
max_download_size_bytes = 1048576
```

## Failure behavior

When policy checks fail, Synapse returns explicit errors (no silent fallback):

- remote denied by policy
- host not allowlisted
- download exceeds configured maximum size
