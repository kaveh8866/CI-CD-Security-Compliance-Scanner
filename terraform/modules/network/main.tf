# OCI network module — public VCN with one public subnet and two ingress rules.
#
# PORTABILITY — the same five resources on the other providers:
#
#   | OCI (here)                | AWS                        | GCP                             |
#   | ------------------------- | -------------------------- | ------------------------------- |
#   | oci_core_vcn              | aws_vpc                    | google_compute_network          |
#   | oci_core_internet_gateway | aws_internet_gateway       | (implicit default route)        |
#   | oci_core_route_table      | aws_route_table + aws_route| google_compute_route            |
#   | oci_core_security_list    | aws_security_group + rules | google_compute_firewall         |
#   | oci_core_subnet           | aws_subnet                 | google_compute_subnetwork       |
#
# The ingress contract (SSH from the operator CIDR, scanner API from the operator
# CIDR) maps to one security-group rule set on AWS and one firewall rule set on
# GCP. Nothing else in the module is OCI-specific.
#
# SECURITY POSTURE — deliberately two rules, not three:
#
#   Inbound 22/tcp             from ssh_allowed_cidr
#   Inbound <scanner_port>/tcp from scanner_allowed_cidr
#   Inbound everything else:   denied by omission.
#
# There is no 80/443 rule because this host serves no web UI. The scanner API is
# a control-plane surface that reads source code; it is never world-reachable.

locals {
  ingress_rules = [
    {
      description = "SSH administration from the operator network"
      port        = 22
      cidr        = var.ssh_allowed_cidr
    },
    {
      description = "Scanner API/dashboard (root-confined, loopback-bound by default)"
      port        = var.scanner_port
      cidr        = var.scanner_allowed_cidr
    },
  ]
}

resource "oci_core_vcn" "this" {
  compartment_id = var.compartment_id
  cidr_block     = var.vcn_cidr
  display_name   = "${var.name_prefix}-vcn"
  dns_label      = var.vcn_dns_label
  freeform_tags  = var.freeform_tags
}

resource "oci_core_internet_gateway" "this" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${var.name_prefix}-igw"
  enabled        = true
  freeform_tags  = var.freeform_tags
}

# Dedicated route table instead of mutating the VCN default, so routing intent is
# visible in the plan and the VCN stays reusable.
resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${var.name_prefix}-public-rt"
  freeform_tags  = var.freeform_tags

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.this.id
    description       = "Default IPv4 egress to the internet gateway"
  }
}

resource "oci_core_security_list" "public" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${var.name_prefix}-sl"
  freeform_tags  = var.freeform_tags

  dynamic "ingress_security_rules" {
    for_each = local.ingress_rules

    content {
      protocol    = "6" # TCP
      source      = ingress_security_rules.value.cidr
      source_type = "CIDR_BLOCK"
      description = ingress_security_rules.value.description

      tcp_options {
        min = ingress_security_rules.value.port
        max = ingress_security_rules.value.port
      }
    }
  }

  # Egress stays open: OS updates and container image pulls are part of boot, and
  # an egress allowlist would have to be re-planned for every dependency host.
  # Filtering belongs at a proxy, not in this sandbox.
  egress_security_rules {
    protocol         = "all"
    destination      = "0.0.0.0/0"
    destination_type = "CIDR_BLOCK"
    description      = "Allow all egress (OS updates, image pulls)"
  }
}

resource "oci_core_subnet" "public" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.this.id
  cidr_block                 = var.subnet_cidr
  display_name               = "${var.name_prefix}-public-subnet"
  dns_label                  = var.subnet_dns_label
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.public.id]
  prohibit_public_ip_on_vnic = false
  freeform_tags              = var.freeform_tags
}
