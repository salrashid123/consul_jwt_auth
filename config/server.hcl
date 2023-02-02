data_dir = "data/"
log_level = "INFO"
node_name = "server"
server = true,
encrypt = "E7deVao78CvZrzayUvwWdlAy4nqBMxzIudNyMEz9VlA=",
encrypt_verify_incoming = true,
encrypt_verify_outgoing = true,
acl = {
  enabled = true
  default_policy = "deny"
  enable_token_persistence = true
},
auto_encrypt {
  allow_tls = true
},
ui = true,
tls {
  defaults {
    ca_file = "consul-agent-ca.pem",
    cert_file = "dc1-server-consul-0.pem",
    key_file = "dc1-server-consul-0-key.pem",
    verify_incoming = true,
    verify_outgoing = true    
  },
}

