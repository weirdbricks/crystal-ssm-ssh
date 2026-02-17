# ---------------------------------------------------------------------------
# Known hosts verification
# Behaviour mirrors ssh's StrictHostKeyChecking=ask:
#   - MATCH    → proceed silently
#   - NOTFOUND → prompt user to accept/reject, save on accept
#                (auto-accepts if STDIN is not a TTY, with a warning)
#   - MISMATCH → hard exit (possible MITM)
# Use --no-known-hosts to skip entirely (insecure)
# ---------------------------------------------------------------------------

module SSHClient
  private def self.key_typemask(key_type : LibSSH2::HostKeyType) : LibSSH2::TypeMask
    key_flag = case key_type
               when LibSSH2::HostKeyType::RSA       then LibSSH2::TypeMask::KEY_SSHRSA
               when LibSSH2::HostKeyType::DSS       then LibSSH2::TypeMask::KEY_SSHDSS
               when LibSSH2::HostKeyType::ECDSA_256 then LibSSH2::TypeMask::KEY_ECDSA_256
               when LibSSH2::HostKeyType::ECDSA_384 then LibSSH2::TypeMask::KEY_ECDSA_384
               when LibSSH2::HostKeyType::ECDSA_521 then LibSSH2::TypeMask::KEY_ECDSA_521
               when LibSSH2::HostKeyType::ED25519   then LibSSH2::TypeMask::KEY_ED25519
               else                                      LibSSH2::TypeMask::KEY_UNKNOWN
               end
    LibSSH2::TypeMask.new(LibSSH2::TypeMask::PLAIN.value | key_flag.value)
  end

  private def self.host_key_fingerprint(session : SSH2::Session) : String
    host_key, _ = session.hostkey
    digest = OpenSSL::Digest.new("SHA256")
    digest.update(host_key)
    "SHA256:#{Base64.strict_encode(digest.final)}"
  rescue
    "(unavailable)"
  end

  def self.check_known_hosts(session : SSH2::Session, host : String, port : Int32,
                             known_hosts_file : String? = nil, debug : Bool = false) : Nil
    known_hosts_file ||= Path.home.join(".ssh", "known_hosts").to_s

    known_hosts = session.knownhosts
    if File.exists?(known_hosts_file)
      begin
        known_hosts.read_file(known_hosts_file)
      rescue ex
        STDERR.puts "Warning: could not read known_hosts: #{ex.message}" if debug
      end
    end

    host_key, key_type = session.hostkey
    check_host = port == 22 ? host : "[#{host}]:#{port}"
    typemask = key_typemask(key_type)

    result = known_hosts.check(host, port, host_key, typemask)

    case result
    when LibSSH2::KnownHostCheck::MATCH
      STDERR.puts "Host key verified (#{key_type}) [#{known_hosts_file}]" if debug
    when LibSSH2::KnownHostCheck::NOTFOUND
      fingerprint = host_key_fingerprint(session)
      STDERR.puts "The authenticity of host '#{check_host}' can't be established."
      STDERR.puts "#{key_type} key fingerprint is #{fingerprint}."

      if STDIN.tty?
        STDERR.print "Are you sure you want to continue connecting? (yes/no) "
        STDERR.flush

        STDIN.cooked do
          answer = STDIN.gets.try(&.strip.downcase)
          unless answer == "yes" || answer == "y"
            STDERR.puts "Connection aborted."
            exit 1
          end
        end
      else
        # Non-interactive: auto-accept like StrictHostKeyChecking=accept-new
        STDERR.puts "Warning: non-interactive session, auto-accepting host key."
      end

      known_hosts.add(check_host, nil, host_key, "", typemask)
      begin
        known_hosts.write_file(known_hosts_file)
        STDERR.puts "Warning: permanently added '#{check_host}' to #{known_hosts_file}."
      rescue ex
        STDERR.puts "Warning: could not write known_hosts: #{ex.message}"
      end
    when LibSSH2::KnownHostCheck::MISMATCH
      STDERR.puts "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      STDERR.puts "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!       @"
      STDERR.puts "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
      STDERR.puts "IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!"
      STDERR.puts "Host key for '#{check_host}' has changed."
      STDERR.puts "If the host key legitimately changed, remove the old entry:"
      STDERR.puts "  ssh-keygen -R #{check_host} -f #{known_hosts_file}"
      STDERR.flush
      exit 1
    end
  end
end
