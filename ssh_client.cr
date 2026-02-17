require "ssh2"
require "option_parser"
require "openssl"
require "base64"
require "awscr-ssm"

require "./src/terminal"
require "./src/ssh_config"
require "./src/known_hosts"
require "./src/agent"
require "./src/ssm"
require "./src/auth"
require "./src/session"
require "./src/keepalive"
require "./src/port_forward"

VERSION = "0.6.0"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

host                = ""
port                = 22
username            = ENV["USER"]? || "root"
identity            = nil   # path to private key file (-i)
command             = nil   # optional one-shot command (positional args after host)
connect_timeout     = 0     # seconds; 0 = OS default
connection_attempts = 1     # retry count on connection failure
debug               = false
no_agent            = false # skip ssh-agent if true
no_known_hosts      = false # skip known_hosts check if true
identities_only     = false # skip agent and auto-discovery if true
server_alive_interval = 0   # keepalive interval in seconds
port_forwards       = [] of PortForward

# SSM options
ssm_secret_path    = nil
aws_region         = ENV["AWS_REGION"]? || ENV["AWS_DEFAULT_REGION"]? || "us-east-1"
aws_access_key_id  = ENV["AWS_ACCESS_KEY_ID"]?
aws_secret_key     = ENV["AWS_SECRET_ACCESS_KEY"]?

# ---------------------------------------------------------------------------
# Option parsing
# ---------------------------------------------------------------------------

OptionParser.parse do |opts|
  opts.banner = "Usage: ssh_client [options] [user@]host [command]"

  opts.separator ""
  opts.separator "Connection options:"

  opts.on("-p PORT", "--port=PORT", "Port to connect on (default: 22)") do |v|
    parsed = v.to_i?
    unless parsed && parsed > 0 && parsed <= 65535
      STDERR.puts "Error: invalid port '#{v}'"
      exit 1
    end
    port = parsed
  end

  opts.on("-l USER", "--login=USER", "Username to log in as") do |v|
    username = v
  end

  opts.on("-o OPTION", "Set an option (ConnectTimeout=N, ConnectionAttempts=N, ServerAliveInterval=N)") do |v|
    key, _, val = v.partition("=")
    case key.strip.downcase
    when "connecttimeout"
      connect_timeout = val.strip.to_i? || 0
    when "connectionattempts"
      connection_attempts = [val.strip.to_i? || 1, 1].max
    when "serveraliveinterval"
      server_alive_interval = val.strip.to_i? || 0
    else
      STDERR.puts "Warning: unsupported option '#{key.strip}'"
    end
  end

  opts.on("-L FORWARD", "Local port forward: local_port:remote_host:remote_port") do |v|
    fwd = PortForward.parse(v)
    if fwd
      port_forwards << fwd
    else
      STDERR.puts "Error: invalid port forward spec '#{v}'"
      exit 1
    end
  end

  opts.separator ""
  opts.separator "Authentication options:"

  opts.on("-i IDENTITY", "--identity=IDENTITY", "Path to private key file") do |v|
    unless File.exists?(v)
      STDERR.puts "Error: key file not found: #{v}"
      exit 1
    end
    identity = v
  end

  opts.on("-A", "--no-agent", "Disable ssh-agent authentication") do
    no_agent = true
  end

  opts.on("--ssm-secret-path PATH", "AWS SSM SecureString path for private key") do |v|
    ssm_secret_path = v
  end

  opts.on("--aws-region REGION", "AWS region (default: AWS_REGION env or us-east-1)") do |v|
    aws_region = v
  end

  opts.on("--aws-access-key-id KEY", "AWS access key ID (overrides AWS_ACCESS_KEY_ID env)") do |v|
    aws_access_key_id = v
  end

  opts.on("--aws-secret-access-key SECRET", "AWS secret access key (overrides AWS_SECRET_ACCESS_KEY env)") do |v|
    aws_secret_key = v
  end

  opts.separator ""
  opts.separator "Host verification options:"

  opts.on("--no-known-hosts", "Skip known_hosts verification (insecure)") do
    no_known_hosts = true
  end

  opts.separator ""
  opts.separator "General options:"

  opts.on("-V", "--version", "Show version and exit") do
    puts "ssh_client #{VERSION}"
    exit 0
  end

  opts.on("-d", "--debug", "Enable debug output") do
    debug = true
  end

  opts.on("-h", "--help", "Show help") do
    puts opts
    exit 0
  end
end

# Bail out if both -i and --ssm-secret-path are given
if identity && ssm_secret_path
  STDERR.puts "Error: --identity and --ssm-secret-path are mutually exclusive."
  exit 1
end

# Parse [user@]host
if ARGV.empty?
  STDERR.puts "Error: host required."
  STDERR.puts "Usage: ssh_client [options] [user@]host [command]"
  exit 1
end

target = ARGV.shift

if target.includes?("@")
  parts    = target.split("@", 2)
  username = parts[0]
  host     = parts[1]
else
  host = target
end

if host.empty?
  STDERR.puts "Error: host cannot be empty."
  exit 1
end

# Remaining ARGV = one-shot command, just like real ssh
unless ARGV.empty?
  command = ARGV.join(" ")
  ARGV.clear
end

# ---------------------------------------------------------------------------
# Apply ~/.ssh/config (CLI flags take precedence)
# ---------------------------------------------------------------------------

config_entry = parse_ssh_config(host)

host                   = config_entry.hostname.not_nil!            if config_entry.hostname
username               = config_entry.user.not_nil!                if config_entry.user && username == (ENV["USER"]? || "root")
port                   = config_entry.port.not_nil!                if config_entry.port && port == 22
identities_only      ||= config_entry.identities_only || false
server_alive_interval  = config_entry.server_alive_interval.not_nil! if config_entry.server_alive_interval && server_alive_interval == 0

if identity.nil? && !config_entry.identity_files.empty?
  identity = config_entry.identity_files.find { |f| File.exists?(f) }
end

# ---------------------------------------------------------------------------
# SSM: fetch private key before opening TCP connection
# ---------------------------------------------------------------------------

key_data = if path = ssm_secret_path
  fetch_ssm_key(path, aws_region, aws_access_key_id, aws_secret_key, debug)
else
  nil
end

STDERR.puts "Connecting to #{username}@#{host}:#{port}..." if debug

timeout    = connect_timeout > 0 ? connect_timeout.seconds : nil
last_error = nil

connection_attempts.times do |attempt|
  begin
    socket  = TCPSocket.new(host, port, connect_timeout: timeout)
    session = SSH2::Session.new(socket)
    begin
      check_known_hosts(session, host, port, config_entry.known_hosts_file, debug) unless no_known_hosts
      authenticate(session, username, identity, key_data, no_agent, identities_only, debug)

      # Start keepalive if configured
      start_keepalive(session, server_alive_interval, debug)

      # Start local port forwards if any
      port_forwards.each do |fwd|
        start_port_forward(session, fwd, debug)
      end

      if cmd = command
        exit run_command(session, cmd)
      else
        run_shell(session)
      end
    ensure
      session.disconnect
    end
    last_error = nil
    break
  rescue ex : IO::TimeoutError
    STDERR.puts "Connection timed out (attempt #{attempt + 1}/#{connection_attempts})" if debug
    last_error = ex
  rescue ex : Socket::ConnectError
    STDERR.puts "Connection refused: #{host}:#{port} (attempt #{attempt + 1}/#{connection_attempts})" if debug
    last_error = ex
  rescue ex : SSH2::SSH2Error
    STDERR.puts "SSH error: #{ex.message}"
    STDERR.flush
    exit 1
  rescue ex
    STDERR.puts "Error: #{ex.message}"
    STDERR.flush
    exit 1
  end
  sleep 1.second if attempt + 1 < connection_attempts
end

if last_error
  STDERR.puts "Failed to connect to #{host}:#{port}"
  STDERR.flush
  exit 1
end
