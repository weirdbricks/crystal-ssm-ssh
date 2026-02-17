# ---------------------------------------------------------------------------
# Authentication: SSM in-memory → ssh-agent → key file → auto-discover
# Respects IdentitiesOnly config directive
# ---------------------------------------------------------------------------

module SSHClient
  def self.authenticate(session : SSH2::Session, username : String,
                        identity : String?, key_data : String?,
                        no_agent : Bool, identities_only : Bool, debug : Bool) : Nil
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

    # 2. SSH agent (unless --no-agent, SSH_AUTH_SOCK not set, or IdentitiesOnly=yes)
    unless no_agent || identities_only || ENV["SSH_AUTH_SOCK"]?.nil?
      return if try_agent_auth(session, username, debug)
    end

    # 3. Explicit key file or auto-discover standard locations
    candidates = if identity
                   [identity]
                 else
                   # Skip auto-discovery if IdentitiesOnly=yes and no explicit -i given
                   if identities_only
                     [] of String
                   else
                     [
                       Path.home.join(".ssh", "id_ed25519").to_s,
                       Path.home.join(".ssh", "id_rsa").to_s,
                       Path.home.join(".ssh", "id_ecdsa").to_s,
                     ]
                   end
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
end
