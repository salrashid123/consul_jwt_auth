data_dir = "data_agent/"
log_level = "INFO"
node_name = "node-1"
server = false,
encrypt = "E7deVao78CvZrzayUvwWdlAy4nqBMxzIudNyMEz9VlA=",

ui = false,
auto_encrypt {
  tls = true
},
tls {
  defaults {
    ca_file = "consul-agent-ca.pem",
    verify_incoming = true,
    verify_outgoing = true    
  },
}
acl {
  tokens {
    agent  = "018bb862-2dca-9a42-0ae4-d967158a8e4f"
  }
}

