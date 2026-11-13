# OCI provider.
#
# Authentication precedence:
#   1. config_file_profile (default "DEFAULT") — reads ~/.oci/config and the API
#      signing key it references. No key material enters this repository or the
#      state file.
#   2. inline user_ocid / fingerprint / private_key_path — for a CI runner that
#      materialises a key at runtime.
#
# PORTABILITY: this block becomes
#   provider "aws"    { region = var.region }            # credentials from the
#                                                        # standard AWS chain
#   provider "google" { project = var.project_id, region = var.region }
# and the `providers = { oci = oci }` pins in main.tf are dropped, because AWS
# and GCP modules do not need the same explicit provider-address pin.

provider "oci" {
  tenancy_ocid        = var.tenancy_ocid
  region              = var.region
  config_file_profile = var.config_file_profile

  user_ocid        = var.user_ocid
  fingerprint      = var.fingerprint
  private_key_path = var.private_key_path
}
