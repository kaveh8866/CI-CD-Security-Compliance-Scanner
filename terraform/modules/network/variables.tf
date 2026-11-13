variable "compartment_id" {
  description = "Compartment that owns the VCN and its child resources."
  type        = string
}

variable "name_prefix" {
  description = "Prefix applied to every resource display name."
  type        = string
}

variable "vcn_cidr" {
  description = "CIDR block for the VCN."
  type        = string

  validation {
    condition     = can(cidrhost(var.vcn_cidr, 0))
    error_message = "vcn_cidr must be a valid IPv4 CIDR block."
  }
}

variable "subnet_cidr" {
  description = "CIDR block for the public subnet. Must sit inside vcn_cidr."
  type        = string

  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "subnet_cidr must be a valid IPv4 CIDR block."
  }
}

variable "ssh_allowed_cidr" {
  description = "Source CIDR allowed to reach 22/tcp."
  type        = string

  validation {
    condition     = can(cidrhost(var.ssh_allowed_cidr, 0))
    error_message = "ssh_allowed_cidr must be a valid IPv4 CIDR block."
  }
}

variable "scanner_allowed_cidr" {
  description = <<-EOT
    Source CIDR allowed to reach the scanner API. The module refuses 0.0.0.0/0:
    an endpoint that returns findings must not be world-reachable, even though
    scan targets are root-confined.
  EOT
  type        = string

  validation {
    condition     = can(cidrhost(var.scanner_allowed_cidr, 0)) && var.scanner_allowed_cidr != "0.0.0.0/0"
    error_message = "scanner_allowed_cidr must be a specific IPv4 CIDR (the operator network), never 0.0.0.0/0."
  }
}

variable "scanner_port" {
  description = "TCP port the scanner API listens on."
  type        = number
  default     = 8300

  validation {
    condition     = var.scanner_port >= 1024 && var.scanner_port <= 65535
    error_message = "scanner_port must be an unprivileged port (1024-65535)."
  }
}

variable "vcn_dns_label" {
  description = "DNS label for the VCN (alphanumeric, no hyphens)."
  type        = string
  default     = "cgscanner"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9]{0,14}$", var.vcn_dns_label))
    error_message = "vcn_dns_label must be alphanumeric, start with a letter and be at most 15 characters."
  }
}

variable "subnet_dns_label" {
  description = "DNS label for the subnet (alphanumeric, no hyphens)."
  type        = string
  default     = "scanner"

  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9]{0,14}$", var.subnet_dns_label))
    error_message = "subnet_dns_label must be alphanumeric, start with a letter and be at most 15 characters."
  }
}

variable "freeform_tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
