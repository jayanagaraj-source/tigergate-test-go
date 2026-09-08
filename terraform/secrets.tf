# Fake static credential used only to exercise secret-scanning rules.
locals {
  fixture_access_key = "AKIAIOSFODNN7EXAMPLE"
  fixture_secret_key = "not-a-real-aws-secret-for-scanner-testing"
}
