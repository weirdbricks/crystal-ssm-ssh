# ssh-client

A Crystal SSH client with AWS SSM Parameter Store integration for in-memory key authentication. Private keys fetched from SSM are never written to disk.

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
crystal build ssh_client.cr -o ssh_client --release
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

# Key from AWS SSM, explicit credentials
./ssh_client \
  --ssm-secret-path /prod/ssh/my-key \
  --aws-region eu-west-1 \
  --aws-access-key-id AKIA... \
  --aws-secret-access-key ... \
  user@host

# With retries and timeout
./ssh_client -i ~/.ssh/id_ed25519 \
  -o ConnectTimeout=5 \
  -o ConnectionAttempts=3 \
  user@host

# Debug mode
./ssh_client -d -i ~/.ssh/id_ed25519 user@host
```

## Options

```
Connection options:
    -p PORT, --port=PORT             Port to connect on (default: 22)
    -l USER, --login=USER            Username to log in as
    -o OPTION                        Set an option (ConnectTimeout=N, ConnectionAttempts=N)

Authentication options:
    -i IDENTITY, --identity=IDENTITY Path to private key file
    --ssm-secret-path PATH           AWS SSM SecureString parameter name/path
    --aws-region REGION              AWS region (default: AWS_REGION env or us-east-1)
    --aws-access-key-id KEY          AWS access key ID (overrides AWS_ACCESS_KEY_ID env)
    --aws-secret-access-key SECRET   AWS secret access key (overrides AWS_SECRET_ACCESS_KEY env)

General options:
    -V, --version                    Show version and exit
    -d, --debug                      Enable debug output
    -h, --help                       Show help
```

## AWS Credentials

When using `--ssm-secret-path`, credentials are resolved in this order:

1. `--aws-access-key-id` / `--aws-secret-access-key` flags
2. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment variables
3. EC2 instance metadata (IMDSv2) — works automatically on EC2 with an IAM role

`AWS_SESSION_TOKEN` is supported for temporary credentials.

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

## Shard Dependencies

This project depends on forked versions of two shards that have been updated for Crystal 1.x compatibility:

- [weirdbricks/awscr-signer](https://github.com/weirdbricks/awscr-signer) — PRs submitted upstream
- [weirdbricks/awscr-ssm](https://github.com/weirdbricks/awscr-ssm) — PRs submitted upstream
