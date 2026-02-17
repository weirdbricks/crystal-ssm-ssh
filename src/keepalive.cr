# ---------------------------------------------------------------------------
# ServerAliveInterval: keepalive packets to prevent idle connection drops
# ---------------------------------------------------------------------------

@[Link("ssh2")]
lib LibSSH2Keepalive
  fun keepalive_config = libssh2_keepalive_config(
    session : Void*,
    want_reply : LibC::Int,
    interval : LibC::UInt,
  ) : Void

  fun keepalive_send = libssh2_keepalive_send(
    session : Void*,
    seconds_to_next : LibC::Int*,
  ) : LibC::Int
end

module SSHClient
  # Maximum consecutive keepalive failures before we consider the connection dead
  KEEPALIVE_MAX_FAILURES = 3

  def self.start_keepalive(session : SSH2::Session, interval : Int32, debug : Bool) : Nil
    return if interval <= 0

    STDERR.puts "ServerAliveInterval: #{interval}s" if debug

    LibSSH2Keepalive.keepalive_config(session.to_unsafe, 1, interval.to_u32)

    spawn do
      consecutive_failures = 0
      loop do
        sleep interval.seconds
        begin
          ret = LibSSH2Keepalive.keepalive_send(session.to_unsafe, out seconds_to_next)
          if ret == 0
            consecutive_failures = 0
            STDERR.puts "Keepalive sent (next in #{seconds_to_next}s)" if debug
          else
            consecutive_failures += 1
            STDERR.puts "Keepalive failed (attempt #{consecutive_failures}/#{KEEPALIVE_MAX_FAILURES})" if debug
          end
        rescue ex
          consecutive_failures += 1
          STDERR.puts "Keepalive error: #{ex.message} (attempt #{consecutive_failures}/#{KEEPALIVE_MAX_FAILURES})" if debug
        end

        if consecutive_failures >= KEEPALIVE_MAX_FAILURES
          STDERR.puts "Connection appears dead after #{KEEPALIVE_MAX_FAILURES} keepalive failures. Disconnecting."
          STDERR.flush
          begin
            session.disconnect
          rescue
          end
          exit 1
        end
      end
    end
  end
end
