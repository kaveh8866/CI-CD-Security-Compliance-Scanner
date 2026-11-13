# Declaring the provider source is what makes `providers = { oci = oci }` in the
# root module resolve to oracle/oci. Without it, OpenTofu assumes hashicorp/oci
# and the plan fails with a provider type mismatch.
terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
    }
  }
}
