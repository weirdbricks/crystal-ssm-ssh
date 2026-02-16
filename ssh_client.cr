require "ssh2"
require "option_parser"
require "awscr-ssm"

VERSION = "0.3.0"

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

# SSM options
ssm_secret_path    = nil    # e.g. /prod/ssh/my-key
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
# Auth: file-based or in-memory (SSM)
# ---------------------------------------------------------------------------

def authenticate(session : SSH2::Session, username : String,
                 identity : String?, key_data : String?,
                 debug : Bool) : Nil
  # SSM in-memory path
  if key_data
    begin
      session.login_with_data(username, key_data, "")
      STDERR.puts "Authenticated via SSM in-memory key" if debug
      return
    rescue ex
      raise "SSM key auth failed: #{ex.message}"
    end
  end

  # File-based path — try explicit key or auto-discover
  candidates = if identity
    [identity]
  else
    [
      File.expand_path("~/.ssh/id_ed25519"),
      File.expand_path("~/.ssh/id_rsa"),
      File.expand_path("~/.ssh/id_ecdsa"),
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

  raise "No valid key found. Use -i to specify a key file or --ssm-secret-path for SSM."
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
# Main
# ---------------------------------------------------------------------------

# Fetch SSM key into memory if requested (before opening TCP connection)
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
      authenticate(session, username, identity, key_data, debug)
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
