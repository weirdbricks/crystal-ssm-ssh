# ---------------------------------------------------------------------------
# One-shot command: stream stdout+stderr, propagate exit code
# ---------------------------------------------------------------------------

module SSHClient
  def self.run_command(session : SSH2::Session, cmd : String) : Int32
    exit_code = 0
    session.open_session do |channel|
      channel.command(cmd)
      buf = Bytes.new(4096)

      stdout_eof = false
      stderr_eof = false

      until stdout_eof && stderr_eof
        # Read stdout unless already at EOF
        unless stdout_eof
          n = channel.read(buf)
          if n > 0
            STDOUT.write(buf[0, n])
            STDOUT.flush
          else
            stdout_eof = true
          end
        end

        # Read stderr unless already at EOF
        unless stderr_eof
          n = channel.read_stderr(buf)
          if n > 0
            STDERR.write(buf[0, n])
            STDERR.flush
          else
            stderr_eof = true
          end
        end
      end

      exit_code = channel.exit_status || 0
    end
    exit_code
  end

  # ---------------------------------------------------------------------------
  # Interactive shell with PTY + SIGWINCH terminal resize
  # ---------------------------------------------------------------------------

  def self.run_shell(session : SSH2::Session) : Nil
    size = terminal_size
    rows = size[:rows]
    cols = size[:cols]

    STDIN.raw!

    session.open_session do |channel|
      channel.request_pty("xterm-256color", [] of Tuple(SSH2::TerminalMode, UInt32), cols, rows)
      channel.shell

      done = Channel(Nil).new

      # Handle terminal resize via SIGWINCH
      Signal::WINCH.trap do
        resize_pty(channel)
      end

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
    Signal::WINCH.reset
    STDIN.cooked!
  end
end
