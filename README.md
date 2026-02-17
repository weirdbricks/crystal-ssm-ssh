# crystal-ssm-ssh

A Crystal SSH client with AWS SSM Parameter Store integration for in-memory key authentication. Private keys fetched from SSM are never written to disk.

> This project was created with the assistance of [Claude](https://claude.ai) (Anthropic's AI assistant).

## Dependencies

- `libssh2` and `libssl` (development headers)
- Crystal >= 1.0.0

On Debian/Ubuntu:
```bash
sudo apt install libssh2-1-dev libssl-dev
```

On macOS:
```bash
brew install libssh2 openssl
```

## Build

```bash
shards install
crystal build ssh_client.cr -o ssh_client --release --no-debug
```

## Usage

```bash
# Interactive shell, key from file
./ssh_client -i ~/.ssh/id_ed25519 user@host

# Interactive shell, non-standard port
./ssh_client -i ~/.ssh/id_ed25519 user@host -p 2222

# One-shot command
./ssh_client -i ~/.ssh/id_ed25519 user@host uptime

# Key from AWS SSM Parameter Store (credentials from environment)
./ssh_client --ssm-secret-path /prod/ssh/my-key user@host

# Key from AWS SSM, explicit credentials (including session token)
./ssh_client \
  --ssm-secret-path /prod/ssh/my-key \
  --aws-region eu-west-1 \
  --aws-access-key-id AKIA... \
  --aws-secret-access-key ... \
  --aws-session-token ... \
  user@host

# With retries and timeout
./ssh_client -i ~/.ssh/id_ed25519 \
  -o ConnectTimeout=5 \
  -o ConnectionAttempts=3 \
  user@host

# Local port forwarding
./ssh_client -i ~/.ssh/id_ed25519 \
  -L 8080:localhost:80 \
  user@host

# Skip ssh-agent and use key file directly
./ssh_client --no-agent -i ~/.ssh/id_ed25519 user@host

# Skip known_hosts verification (insecure, use with caution)
./ssh_client --no-known-hosts -i ~/.ssh/id_ed25519 user@host

# Debug/verbose mode
./ssh_client -d -i ~/.ssh/id_ed25519 user@host
./ssh_client -v -i ~/.ssh/id_ed25519 user@host
```

## Options

```
Connection options:
    -p PORT, --port=PORT             Port to connect on (default: 22)
    -l USER, --login=USER            Username to log in as
    -o OPTION                        Set an option (ConnectTimeout=N, ConnectionAttempts=N, ServerAliveInterval=N)
    -L FORWARD                       Local port forward: local_port:remote_host:remote_port

Authentication options:
    -i IDENTITY, --identity=IDENTITY Path to private key file
    --no-agent                       Disable ssh-agent authentication
    --ssm-secret-path PATH           AWS SSM SecureString parameter name/path
    --aws-region REGION              AWS region (default: AWS_REGION env or us-east-1)
    --aws-access-key-id KEY          AWS access key ID (overrides AWS_ACCESS_KEY_ID env)
    --aws-secret-access-key SECRET   AWS secret access key (overrides AWS_SECRET_ACCESS_KEY env)
    --aws-session-token TOKEN        AWS session token (overrides AWS_SESSION_TOKEN env)

Host verification options:
    --no-known-hosts                 Skip known_hosts verification (insecure)

General options:
    -V, --version                    Show version and exit
    -d, --debug                      Enable debug output
    -v, --verbose                    Enable debug output (alias for -d)
    -h, --help                       Show help
```

## Authentication Order

When connecting, authentication is attempted in this order:

1. **SSM in-memory key** — if `--ssm-secret-path` is given
2. **ssh-agent** — if `SSH_AUTH_SOCK` is set and `--no-agent` is not given
3. **Key file** — explicit `-i` path, or auto-discovery of `~/.ssh/id_ed25519`, `id_rsa`, `id_ecdsa`

## ~/.ssh/config Support

The following directives are read from `~/.ssh/config`:

- `Host` — pattern matching (simple wildcards supported; negation patterns like `!host` are not currently handled)
- `HostName` — hostname alias resolution
- `User` — default username
- `Port` — default port
- `IdentityFile` — key file path
- `IdentitiesOnly` — restrict to configured keys only
- `UserKnownHostsFile` — custom known hosts file path
- `ServerAliveInterval` — keepalive interval

CLI flags always take precedence over config file values.

## Host Key Verification

Known hosts are checked against `~/.ssh/known_hosts` on every connection. On first connection to an unknown host in an interactive terminal, you will be prompted to accept the key. In non-interactive sessions (piped input), new host keys are auto-accepted with a warning (equivalent to `StrictHostKeyChecking=accept-new`). A key mismatch causes an immediate exit with an error.

Use `--no-known-hosts` to skip verification entirely (not recommended for production).

## AWS Credentials

When using `--ssm-secret-path`, credentials are resolved in this order:

1. `--aws-access-key-id` / `--aws-secret-access-key` / `--aws-session-token` flags
2. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` environment variables
3. EC2 instance metadata (IMDSv2) — works automatically on EC2 with an IAM role

`AWS_SESSION_TOKEN` is fully supported for temporary credentials (STS, SSO).

## SSM Parameter Setup

Store your private key as a `SecureString` parameter:

```bash
aws ssm put-parameter \
  --name /prod/ssh/my-key \
  --value "$(cat ~/.ssh/id_ed25519)" \
  --type SecureString \
  --region us-east-1
```

The IAM principal needs `ssm:GetParameter` permission on the parameter.

## Linting

This project uses [Ameba](https://github.com/crystal-ameba/ameba) for static code analysis:

```bash
# Install (included as a dev dependency)
shards install

# Run linter
./bin/ameba

# Run on specific files
./bin/ameba src/ssh_config.cr

# Run with specific rules
./bin/ameba --only Style/RedundantBegin
```

Configuration is in `.ameba.yml`.

## Shard Dependencies

This project depends on forked versions of two shards that have been updated for Crystal 1.x compatibility:

- [weirdbricks/awscr-signer](https://github.com/weirdbricks/awscr-signer) — PRs submitted upstream
- [weirdbricks/awscr-ssm](https://github.com/weirdbricks/awscr-ssm) — PRs submitted upstream
