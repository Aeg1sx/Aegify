# Example only: bind this policy to the production dashboard workload identity.
path "kv/data/codeguard/production/dashboard" {
  capabilities = ["read"]
}

path "kv/metadata/codeguard/production/dashboard" {
  capabilities = ["read"]
}
