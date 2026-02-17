# ---------------------------------------------------------------------------
# ~/.ssh/config parser
# Supports: Host, HostName, User, Port, IdentityFile, UserKnownHostsFile,
#           IdentitiesOnly, ServerAliveInterval
# ---------------------------------------------------------------------------

struct SshConfigEntry
  property hostname : String?
  property user : String?
  property port : Int32?
  property identity_files : Array(String)
  property known_hosts_file : String?
  property identities_only : Bool?
  property server_alive_interval : Int32?

  def initialize
    @hostname               = nil
    @user                   = nil
    @port                   = nil
    @identity_files         = [] of String
    @known_hosts_file       = nil
    @identities_only        = nil
    @server_alive_interval  = nil
  end
end

def parse_ssh_config(target_host : String) : SshConfigEntry
  entry  = SshConfigEntry.new
  config = Path.home.join(".ssh", "config").to_s
  return entry unless File.exists?(config)

  current_patterns = [] of String
  active           = false

  File.each_line(config) do |raw|
    line = raw.strip
    next if line.empty? || line.starts_with?("#")

    parts = line.split(/\s+/, 2)
    next if parts.size < 2
    key = parts[0]
    val = parts[1].strip

    case key.downcase
    when "host"
      current_patterns = val.split
      active = current_patterns.any? { |pat| File.match?(pat, target_host) }
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
      when "userknownhostsfile"
        entry.known_hosts_file ||= Path.home.join(val.lstrip("~/")).to_s
      when "identitiesonly"
        entry.identities_only ||= (val.downcase == "yes")
      when "serveraliveinterval"
        entry.server_alive_interval ||= val.to_i?
      end
    end
  end

  entry
end
