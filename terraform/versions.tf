# =============================================================================
# CI/CD Security & Compliance Scanner — OpenTofu contract
# =============================================================================
# OCI is the validated target. The provider constraint is pinned loosely enough
# to accept security fixes and tightly enough that a major release cannot change
# behaviour silently.
#
# PORTABILITY: the equivalent provider blocks are
#   AWS: provider "aws"     { region = var.region }
#   GCP: provider "google" { project = var.project_id, region = var.region }
# Only the module bodies change; the root variables and outputs stay the same.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 6.20.0, < 8.0.0"
    }
  }

  # State stays local (gitignored) for this portfolio. For a shared environment,
  # swap in an OCI Object Storage backend with state locking:
  #
  # backend "oci" {
  #   bucket    = "cloudguard-scanner-tfstate"
  #   namespace = "<object-storage-namespace>"
  #   key       = "scanner/terraform.tfstate"
  #   region    = "eu-frankfurt-1"
  # }
}
