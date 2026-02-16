# ---------------------------------------------------------------------------
# AWS SSM Parameter Store: fetch private key into memory, never touch disk
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
