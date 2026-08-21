# Example only: bind this policy to the production dashboard workload identity.
path "kv/data/aegify/production/dashboard" {
  capabilities = ["read"]
}

path "kv/metadata/aegify/production/dashboard" {
  capabilities = ["read"]
}
