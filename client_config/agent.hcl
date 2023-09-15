data_dir = "data_agent/"
log_level = "INFO"
node_name = "node-1"
server = false,
encrypt = "2rYILsPDvVKYEWJYtUtLADkfE4iEF3mSzfZGKOqxykc=",

ui_config  {
  enabled = false,
},

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
    agent  = "bd0a1f02-6777-64d0-ed2e-c565804dd6b6"
  }
}

