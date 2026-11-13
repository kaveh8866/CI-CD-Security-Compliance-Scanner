# Input contract for the OCI environment.
#
# Anything that differs between operators, clouds or CloudGuard envelopes is a
# variable; nothing environment-specific is hard-coded outside terraform.tfvars.
#
# PORTABILITY: the shared concepts map as follows —
#   region -> AWS aws_region / GCP region
#   vcn_cidr, subnet_cidr -> VPC CIDR / subnetwork range
#   instance_shape + ocpus + memory -> instance_type / machine_type
#   scanner_port + scanner_allowed_cidr -> one security-group or firewall rule
#
# The names below are provider-neutral wherever the concept is shared.

# -----------------------------------------------------------------------------
# OCI identity
# -----------------------------------------------------------------------------

variable "tenancy_ocid" {
  description = "OCI tenancy OCID. Also scopes the availability-domain lookup."
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.tenancy\\.", var.tenancy_ocid))
    error_message = "tenancy_ocid must be an OCI tenancy OCID."
  }
}

variable "compartment_ocid" {
  description = "Compartment OCID that owns the VCN and the scanner instance."
  type        = string

  validation {
    condition     = can(regex("^ocid1\\.(compartment|tenancy)\\.", var.compartment_ocid))
    error_message = "compartment_ocid must be an OCI compartment (or tenancy) OCID."
  }
}

variable "region" {
  description = "OCI region identifier, e.g. eu-frankfurt-1."
  type        = string

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.region))
    error_message = "region must be an OCI region identifier such as eu-frankfurt-1."
  }
}

variable "user_ocid" {
  description = "OCI user OCID for inline API-key auth. Leave null to use config_file_profile."
  type        = string
  default     = null
}

variable "fingerprint" {
  description = "Fingerprint of the API signing key. Leave null to use config_file_profile."
  type        = string
  default     = null
}

variable "private_key_path" {
  description = "Path to the OCI API signing key (outside this repository). Leave null to use config_file_profile."
  type        = string
  default     = null
}

variable "config_file_profile" {
  description = "Profile name inside ~/.oci/config."
  type        = string
  default     = null
}

# -----------------------------------------------------------------------------
# Naming and tagging
# -----------------------------------------------------------------------------

variable "project_name" {
  description = "Short slug used to prefix every resource name and the on-host install directory."
  type        = string
  default     = "cloudguard-scanner"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.project_name))
    error_message = "project_name must be lowercase alphanumeric with hyphens, 2-31 characters."
  }
}

variable "environment" {
  description = "Environment suffix (dev, staging, prod)."
  type        = string
  default     = "dev"
}

variable "freeform_tags" {
  description = "Freeform tags applied to every resource (cost tracking / CloudGuard metadata)."
  type        = map(string)
  default = {
    project  = "cicd-security-compliance-scanner"
    owner    = "cloudguard"
    tier     = "always-free"
    severity = "high"
  }
}

# -----------------------------------------------------------------------------
# Network
# -----------------------------------------------------------------------------

variable "vcn_cidr" {
  description = "CIDR for the VCN. Deliberately disjoint from the other portfolio projects so none can collide in one tenancy."
  type        = string
  default     = "10.7.0.0/16"

  validation {
    condition     = can(cidrhost(var.vcn_cidr, 0))
    error_message = "vcn_cidr must be a valid IPv4 CIDR block."
  }
}

variable "subnet_cidr" {
  description = "CIDR for the public subnet. Must sit inside vcn_cidr."
  type        = string
  default     = "10.7.1.0/24"

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "subnet_cidr must be a valid IPv4 CIDR block."
  }
}

variable "ssh_allowed_cidr" {
  description = "Source CIDR allowed to reach SSH (22). Use your own address (/32), not the internet."
  type        = string

  validation {
    condition     = can(cidrhost(var.ssh_allowed_cidr, 0))
    error_message = "ssh_allowed_cidr must be a valid IPv4 CIDR block."
  }
}

variable "scanner_allowed_cidr" {
  description = <<-EOT
    Source CIDR allowed to reach the scanner API/dashboard port. Refused if open
    to the world: the API returns findings and can be pointed at source code,
    so exposure is limited to the operator network, a VPN range or a bastion.
  EOT
  type        = string

  validation {
    condition     = can(cidrhost(var.scanner_allowed_cidr, 0)) && var.scanner_allowed_cidr != "0.0.0.0/0"
    error_message = "scanner_allowed_cidr must be a specific IPv4 CIDR (e.g. 203.0.113.10/32), never 0.0.0.0/0."
  }
}

variable "scanner_port" {
  description = "TCP port the scanner API listens on (unprivileged)."
  type        = number
  default     = 8300

  validation {
    condition     = var.scanner_port >= 1024 && var.scanner_port <= 65535
    error_message = "scanner_port must be between 1024 and 65535."
  }
}

# -----------------------------------------------------------------------------
# Compute
# -----------------------------------------------------------------------------

variable "instance_shape" {
  description = "Compute shape. VM.Standard.A1.Flex is Always Free eligible (ARM, up to 2 OCPU / 12 GB in current allowances)."
  type        = string
  default     = "VM.Standard.A1.Flex"
}

variable "instance_ocpus" {
  description = "OCPUs for flex shapes. The scanner is capped at 0.25 CPU, so 1 OCPU is generous."
  type        = number
  default     = 1

  validation {
    condition     = var.instance_ocpus >= 1 && var.instance_ocpus <= 2
    error_message = "instance_ocpus must be between 1 and 2 to stay inside the Always Free A1 envelope."
  }
}

variable "instance_memory_gbs" {
  description = "Memory in GB for flex shapes. 6 GB leaves room for Docker, a image pull and a full scan while staying free."
  type        = number
  default     = 6

  validation {
    condition     = var.instance_memory_gbs >= 1 && var.instance_memory_gbs <= 12
    error_message = "instance_memory_gbs must be between 1 and 12 to stay inside the Always Free A1 envelope."
  }
}

variable "boot_volume_size_gbs" {
  description = "Boot volume size in GB. Holds the OS, Docker and the scanner image."
  type        = number
  default     = 50

  validation {
    condition     = var.boot_volume_size_gbs >= 50
    error_message = "boot_volume_size_gbs must be at least 50 for Ubuntu images on A1 shapes."
  }
}

variable "availability_domain" {
  description = "Availability domain name. Leave null to use the first AD; pin AD-2 when AD-1 reports 'Out of host capacity'."
  type        = string
  default     = null
}

variable "hostname_label" {
  description = "Hostname label for the VNIC (no hyphens, max 15 characters)."
  type        = string
  default     = "scanner"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9]{0,14}$", var.hostname_label))
    error_message = "hostname_label must be alphanumeric, start with a letter and be at most 15 characters."
  }
}

variable "ssh_public_key" {
  description = "SSH public key content (not a path, not a private key) injected into instance metadata."
  type        = string

  validation {
    # Refuses a private key pasted by mistake: the most common provisioning
    # error, and a silent credential leak if it ever reached state.
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) ", var.ssh_public_key))
    error_message = "ssh_public_key must be an OpenSSH public key beginning with ssh-ed25519, ssh-rsa or ecdsa-sha2-*. Never paste a private key."
  }
}

variable "image_id" {
  description = "Pin a specific image OCID. Leave null to resolve the newest Ubuntu build for the shape."
  type        = string
  default     = null
}

variable "image_operating_system" {
  description = "Operating system to resolve when image_id is null."
  type        = string
  default     = "Canonical Ubuntu"
}

variable "image_operating_system_version" {
  description = "OS version to resolve when image_id is null."
  type        = string
  default     = "24.04"
}
