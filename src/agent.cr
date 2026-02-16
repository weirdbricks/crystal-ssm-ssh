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
