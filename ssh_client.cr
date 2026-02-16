require "ssh2"
require "option_parser"
require "awscr-ssm"

VERSION = "0.4.0"

# ---------------------------------------------------------------------------
# Terminal size via ioctl — no subprocess required
# ---------------------------------------------------------------------------

lib LibTermSize
  struct Winsize
    ws_row    : LibC::UShort
    ws_col    : LibC::UShort
    ws_xpixel : LibC::UShort
    ws_ypixel : LibC::UShort
  end

  TIOCGWINSZ = {% if flag?(:darwin) %} 0x40087468u64 {% else %} 0x5413u64 {% end %}

  fun ioctl(fd : LibC::Int, request : LibC::ULong, ...) : LibC::Int
end

def terminal_size : {rows: Int32, cols: Int32}
  ws  = LibTermSize::Winsize.new
  ret = LibTermSize.ioctl(STDOUT.fd, LibTermSize::TIOCGWINSZ, pointerof(ws))
  if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0
    {rows: ws.ws_row.to_i, cols: ws.ws_col.to_i}
  else
    {rows: 24, cols: 80}
  end
end

# ---------------------------------------------------------------------------
# ~/.ssh/config parser
# Supports: Host, HostName, User, Port, IdentityFile, ServerAliveInterval
# ---------------------------------------------------------------------------

struct SshConfigEntry
  property hostname : String?
  property user : String?
  property port : Int32?
  property identity_files : Array(String)

  def initialize
    @hostname       = nil
    @user           = nil
    @port           = nil
    @identity_files = [] of String
  end
end

def parse_ssh_config(target_host : String) : SshConfigEntry
  entry   = SshConfigEntry.new
  config  = Path.home.join(".ssh", "config").to_s
  return entry unless File.exists?(config)

  current_patterns = [] of String
  active           = false

  File.each_line(config) do |raw|
    line = raw.strip
    next if line.empty? || line.starts_with?("#")

    parts = line.split(/\s+/, 2)
    next if parts.size < 2
    key = parts[0]
    val = parts[1]
    val = val.strip

    case key.downcase
    when "host"
      # Each "Host" stanza may have multiple space-separated patterns
      current_patterns = val.split
      active = current_patterns.any? do |pat|
        File.match?(pat, target_host)
      end
    else
      next unless active
      case key.downcase
      when "hostname"
        entry.hostname ||= val
      when "user"
        entry.user ||= val
      when "port"
        entry.port ||= val.to_i?
      when "identityfile"
        entry.identity_files << Path.home.join(val.lstrip("~/")).to_s
      end
    end
  end

  entry
end

# ---------------------------------------------------------------------------
# Known hosts verification
# ---------------------------------------------------------------------------

def check_known_hosts(session : SSH2::Session, host : String, port : Int32,
                      debug : Bool) : Nil
  known_hosts_file = File.expand_path("~/.ssh/known_hosts")
  return unless File.exists?(known_hosts_file)

  known_hosts = session.knownhosts
  begin
    known_hosts.read_file(known_hosts_file)
  rescue ex
    STDERR.puts "Warning: could not read known_hosts: #{ex.message}" if debug
    return
  end

  host_key, key_type = session.hostkey
  check_host = port == 22 ? host : "[#{host}]:#{port}"

  result = known_hosts.check(host, port, host_key, LibSSH2::TypeMask::PLAIN)

  case result
  when LibSSH2::KnownHostCheck::MATCH
    STDERR.puts "Host key verified (#{key_type})" if debug
  when LibSSH2::KnownHostCheck::NOTFOUND
    # Auto-add on first connection, like ssh's StrictHostKeyChecking=accept-new
    STDERR.puts "Warning: host '#{check_host}' not in known_hosts — adding automatically." if debug
    known_hosts.add(check_host, nil, host_key, "", LibSSH2::TypeMask::PLAIN)
    begin
      known_hosts.write_file(known_hosts_file)
      STDERR.puts "Host key saved to #{known_hosts_file}" if debug
    rescue ex
      STDERR.puts "Warning: could not write known_hosts: #{ex.message}"
    end
  when LibSSH2::KnownHostCheck::MISMATCH
    STDERR.puts "ERROR: Host key mismatch for '#{check_host}'!"
    STDERR.puts "This could indicate a man-in-the-middle attack."
    STDERR.puts "If the host key legitimately changed, remove the old entry from #{known_hosts_file}"
    STDERR.flush
    exit 1
  end
end

# ---------------------------------------------------------------------------
# SSH agent authentication
# ---------------------------------------------------------------------------

def try_agent_auth(session : SSH2::Session, username : String,
                   debug : Bool) : Bool
  agent = SSH2::Agent.new(session)
  agent.connect
  agent.list_identities
  agent.authenticate(username)
  STDERR.puts "Authenticated via ssh-agent" if debug
  true
rescue ex
  STDERR.puts "ssh-agent not available: #{ex.message}" if debug
  false
end

# ---------------------------------------------------------------------------
# SSM: fetch private key from Parameter Store, never write to disk
# ---------------------------------------------------------------------------

def fetch_ssm_key(path : String, region : String,
                  access_key_id : String?, secret_key : String?,
                  debug : Bool) : String
  STDERR.puts "Fetching SSH key from SSM: #{path}" if debug

  client = if access_key_id && secret_key
    creds = Awscr::SSM::SimpleCredentials.new(access_key_id, secret_key)
    Awscr::SSM::Client.new(region, creds)
  else
    # Falls back to instance role via IMDSv2 / env vars automatically
    Awscr::SSM::Client.new(region)
  end

  begin
    parameter = client.get_parameter(path, with_decryption: true)
  rescue ex
    STDERR.puts "Error: failed to fetch SSM parameter '#{path}': #{ex.message}"
    exit 1
  end

  STDERR.puts "SSM key fetched (never written to disk)" if debug
  parameter
end

# ---------------------------------------------------------------------------
# Auth: SSM in-memory → agent → key file → auto-discover
# ---------------------------------------------------------------------------

def authenticate(session : SSH2::Session, username : String,
                 identity : String?, key_data : String?,
                 no_agent : Bool, debug : Bool) : Nil
  # 1. SSM in-memory key
  if key_data
    begin
      session.login_with_data(username, key_data, "")
      STDERR.puts "Authenticated via SSM in-memory key" if debug
      return
    rescue ex
      raise "SSM key auth failed: #{ex.message}"
    end
  end

  # 2. SSH agent (unless --no-agent or SSH_AUTH_SOCK not set)
  unless no_agent || ENV["SSH_AUTH_SOCK"]?.nil?
    return if try_agent_auth(session, username, debug)
  end

  # 3. Explicit key file or auto-discover
  candidates = if identity
    [identity]
  else
    [
      Path.home.join(".ssh", "id_ed25519").to_s,
      Path.home.join(".ssh", "id_rsa").to_s,
      Path.home.join(".ssh", "id_ecdsa").to_s,
    ]
  end

  candidates.each do |key|
    next unless File.exists?(key)
    pub = "#{key}.pub"
    begin
      session.login_with_pubkey(username, key, pub)
      STDERR.puts "Authenticated with #{key}" if debug
      return
    rescue
      # try next
    end
  end

  raise "No valid authentication method succeeded. Use -i, --ssm-secret-path, or ensure ssh-agent is running."
end

# ---------------------------------------------------------------------------
# One-shot command: run and stream output, return remote exit code
# ---------------------------------------------------------------------------

def run_command(session : SSH2::Session, cmd : String) : Int32
  exit_code = 0
  session.open_session do |channel|
    channel.command(cmd)
    buf = Bytes.new(4096)
    loop do
      n = channel.read(buf)
      break if n <= 0
      STDOUT.write(buf[0, n])
    end
    STDOUT.flush
    exit_code = channel.exit_status || 0
  end
  exit_code
end

# ---------------------------------------------------------------------------
# Interactive shell with PTY
# ---------------------------------------------------------------------------

def run_shell(session : SSH2::Session) : Nil
  size = terminal_size
  rows = size[:rows]
  cols = size[:cols]

  STDIN.raw!

  session.open_session do |channel|
    channel.request_pty("xterm-256color", [] of Tuple(SSH2::TerminalMode, UInt32), cols, rows)
    channel.shell

    done = Channel(Nil).new

    # remote → local stdout
    spawn do
      buf = Bytes.new(4096)
      loop do
        n = channel.read(buf)
        break if n <= 0
        STDOUT.write(buf[0, n])
        STDOUT.flush
      end
      done.send(nil)
    end

    # local stdin → remote
    spawn do
      buf = Bytes.new(256)
      loop do
        n = STDIN.read(buf)
        break if n <= 0
        channel.write(buf[0, n])
      end
      done.send(nil)
    end

    done.receive
  end
ensure
  STDIN.cooked!
end

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

  opts.on("-o OPTION", "Set an option (ConnectTimeout=N, ConnectionAttempts=N)") do |v|
    key, _, val = v.partition("=")
    case key.strip.downcase
    when "connecttimeout"
      connect_timeout = val.strip.to_i? || 0
    when "connectionattempts"
      connection_attempts = [val.strip.to_i? || 1, 1].max
    else
      STDERR.puts "Warning: unsupported option '#{key.strip}'"
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

# HostName alias resolution
host = config_entry.hostname.not_nil! if config_entry.hostname

# Apply config values only if not already set by CLI flags
username = config_entry.user.not_nil! if config_entry.user && username == (ENV["USER"]? || "root")
port     = config_entry.port.not_nil! if config_entry.port && port == 22
if identity.nil? && !config_entry.identity_files.empty?
  # Use first identity from config that exists on disk
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
      check_known_hosts(session, host, port, debug) unless no_known_hosts
      authenticate(session, username, identity, key_data, no_agent, debug)
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
