terraform {
  required_version = ">= 1.8"
  required_providers {
    alicloud = { source = "aliyun/alicloud", version = ">= 1.240.0" }
  }
  # The state holds the ntfy webhook URL (a capability) and the Healthchecks URL: OpenTofu state encryption,
  # passphrase from TF_VAR_state_passphrase (never committed). Unencrypted state is refused (no fallback).
  encryption {
    key_provider "pbkdf2" "state" {
      passphrase = var.state_passphrase
    }
    method "aes_gcm" "state" {
      keys = key_provider.pbkdf2.state
    }
    state {
      method   = method.aes_gcm.state
      enforced = true
    }
    plan {
      method   = method.aes_gcm.state
      enforced = true
    }
  }
}
