# ---------------------------------------------------------------------------
# Terminal size via ioctl and PTY resize via SIGWINCH
# ---------------------------------------------------------------------------

lib LibTermSize
  struct Winsize
    ws_row : LibC::UShort
    ws_col : LibC::UShort
    ws_xpixel : LibC::UShort
    ws_ypixel : LibC::UShort
  end

  TIOCGWINSZ = {% if flag?(:darwin) %} 0x40087468u64 {% else %} 0x5413u64 {% end %}

  fun ioctl(fd : LibC::Int, request : LibC::ULong, ...) : LibC::Int
end

@[Link("ssh2")]
lib LibSSH2Resize
  fun channel_request_pty_size = libssh2_channel_request_pty_size_ex(
    channel : Void*,
    width : LibC::Int,
    height : LibC::Int,
    width_px : LibC::Int,
    height_px : LibC::Int,
  ) : LibC::Int
end

module SSHClient
  def self.terminal_size : {rows: Int32, cols: Int32}
    ws = LibTermSize::Winsize.new
    ret = LibTermSize.ioctl(STDOUT.fd, LibTermSize::TIOCGWINSZ, pointerof(ws))
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0
      {rows: ws.ws_row.to_i, cols: ws.ws_col.to_i}
    else
      {rows: 24, cols: 80}
    end
  end

  def self.resize_pty(channel : SSH2::Channel) : Nil
    size = terminal_size
    LibSSH2Resize.channel_request_pty_size(
      channel.to_unsafe,
      size[:cols], size[:rows], 0, 0
    )
  end
end
