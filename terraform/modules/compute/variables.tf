variable "compartment_id" {
  description = "Compartment that owns the instance."
  type        = string
}

variable "tenancy_ocid" {
  description = "Tenancy OCID — availability domains are tenancy-scoped."
  type        = string
}

variable "name_prefix" {
  description = "Prefix applied to every resource display name."
  type        = string
}

variable "subnet_id" {
  description = "Subnet the primary VNIC attaches to."
  type        = string
}

variable "availability_domain" {
  description = "Availability domain name. Leave null to use the first AD in the region."
  type        = string
  default     = null
}

variable "instance_shape" {
  description = "Compute shape. VM.Standard.A1.Flex is Always Free eligible."
  type        = string
}

variable "instance_ocpus" {
  description = "OCPUs for flex shapes."
  type        = number
}

variable "instance_memory_gbs" {
  description = "Memory in GB for flex shapes."
  type        = number
}

variable "boot_volume_size_gbs" {
  description = "Boot volume size in GB."
  type        = number
}

variable "ssh_public_key" {
  description = "SSH public key content injected into instance metadata. The private half never enters Terraform."
  type        = string

  validation {
    # Refuses a private key pasted by mistake — the most common OCI provisioning
    # error, and a silent credential leak if it reached state.
    condition     = can(regex("^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) ", var.ssh_public_key))
    error_message = "ssh_public_key must be an OpenSSH public key beginning with ssh-ed25519, ssh-rsa or ecdsa-sha2-*. Never paste a private key."
  }
}

variable "user_data" {
  description = "Base64-encoded cloud-init payload."
  type        = string
}

variable "hostname_label" {
  description = "Hostname label for the VNIC (no hyphens, max 15 characters)."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9]{0,14}$", var.hostname_label))
    error_message = "hostname_label must be alphanumeric, start with a letter and be at most 15 characters."
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

variable "image_os_version" {
  description = "OS version to resolve when image_id is null."
  type        = string
  default     = "24.04"
}

variable "freeform_tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
