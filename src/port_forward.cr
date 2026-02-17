# ---------------------------------------------------------------------------
# Local port forwarding: -L local_port:remote_host:remote_port
# Opens a local TCP listener that tunnels through SSH to the remote host
# ---------------------------------------------------------------------------

@[Link("ssh2")]
lib LibSSH2DirectTcpip
  fun channel_direct_tcpip = libssh2_channel_direct_tcpip_ex(
    session : Void*,
    host    : LibC::Char*,
    port    : LibC::Int,
    shost   : LibC::Char*,
    sport   : LibC::Int
  ) : Void*
end

struct PortForward
  property local_port : Int32
  property remote_host : String
  property remote_port : Int32

  def initialize(@local_port, @remote_host, @remote_port)
  end

  def self.parse(spec : String) : PortForward?
    # Format: local_port:remote_host:remote_port
    parts = spec.split(":", 3)
    return nil unless parts.size == 3

    local_port = parts[0].to_i?
    remote_port = parts[2].to_i?
    return nil unless local_port && remote_port

    PortForward.new(local_port, parts[1], remote_port)
  end
end

def start_port_forward(session : SSH2::Session, forward : PortForward, debug : Bool) : Nil
  server = TCPServer.new("127.0.0.1", forward.local_port)
  STDERR.puts "Local port forwarding: 127.0.0.1:#{forward.local_port} -> #{forward.remote_host}:#{forward.remote_port}" if debug

  spawn do
    loop do
      client = server.accept
      STDERR.puts "Accepted connection on local port #{forward.local_port}" if debug

      spawn do
        begin
          # Open direct-tcpip channel to remote host
          channel_ptr = LibSSH2DirectTcpip.channel_direct_tcpip(
            session.to_unsafe,
            forward.remote_host,
            forward.remote_port,
            "127.0.0.1",
            forward.local_port
          )

          raise "Failed to open direct-tcpip channel" if channel_ptr.null?

          channel = SSH2::Channel.new(session, channel_ptr)

          # Bidirectional tunnel
          done = Channel(Nil).new

          # local → remote
          spawn do
            buf = Bytes.new(4096)
            loop do
              n = client.read(buf)
              break if n <= 0
              channel.write(buf[0, n])
            end
            done.send(nil)
          end

          # remote → local
          spawn do
            buf = Bytes.new(4096)
            loop do
              n = channel.read(buf)
              break if n <= 0
              client.write(buf[0, n])
              client.flush
            end
            done.send(nil)
          end

          done.receive
        rescue ex
          STDERR.puts "Port forward error: #{ex.message}" if debug
        ensure
          client.close
        end
      end
    end
  rescue ex
    STDERR.puts "Port forward listener error: #{ex.message}"
  end
end
