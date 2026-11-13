# Root module — wires the network and compute modules together.
#
# PORTABILITY (AWS / GCP), in one place:
#
#   OCI VCN + IGW + route table + security list + subnet
#     ≈ AWS  VPC + internet gateway + route table + security group + subnet
#     ≈ GCP  VPC network + implicit default route + firewall rule + subnetwork
#
#   OCI oci_core_instance (VM.Standard.A1.Flex)
#     ≈ AWS  aws_instance (t4g.small / t3.micro, free tier eligible)
#     ≈ GCP  google_compute_instance (e2-micro, free tier in us-central1)
#
#   OCI metadata.user_data (base64 cloud-init)
#     ≈ AWS  user_data            (plain text)
#     ≈ GCP  metadata_startup_script
#
# The module boundary is the portable part: `network` exposes subnet_id and the
# ingress inventory; `compute` consumes subnet_id and returns public_ip. A port
# replaces the two module bodies and keeps this file and every variable name.

locals {
  name_prefix = "${var.project_name}-${var.environment}"

  tags = merge(var.freeform_tags, {
    environment = var.environment
    managed_by  = "opentofu"
    stage       = "2-iac"
  })

  # Cloud-init prepares the host and nothing else: Docker, a hardened daemon
  # config, an empty application directory. It deliberately carries **no
  # credential, no webhook and no .env** — user-data is readable from the
  # instance metadata service by anything on the host, so a secret placed here
  # is a secret published. The stack is installed over SSH in the deploy stage.
  user_data = base64encode(
    templatefile("${path.module}/cloud-init.yaml.tftpl", {
      project_name = var.project_name
      scanner_port = var.scanner_port
      install_dir  = "/opt/${var.project_name}"
      repository   = "https://github.com/kaveh8866/CI-CD-Security-Compliance-Scanner.git"
    })
  )
}

module "network" {
  source = "./modules/network"

  # Pin the provider address. Without this, OpenTofu infers hashicorp/oci for the
  # child module while the root uses oracle/oci; the two addresses do not share
  # configuration and the apply fails with "did not find a proper configuration
  # for tenancy".
  providers = { oci = oci }

  compartment_id       = var.compartment_ocid
  name_prefix          = local.name_prefix
  vcn_cidr             = var.vcn_cidr
  subnet_cidr          = var.subnet_cidr
  ssh_allowed_cidr     = var.ssh_allowed_cidr
  scanner_allowed_cidr = var.scanner_allowed_cidr
  scanner_port         = var.scanner_port
  vcn_dns_label        = "cgscanner"
  subnet_dns_label     = "scanner"
  freeform_tags        = local.tags
}

module "compute" {
  source = "./modules/compute"

  providers = { oci = oci }

  compartment_id         = var.compartment_ocid
  tenancy_ocid           = var.tenancy_ocid
  name_prefix            = local.name_prefix
  subnet_id              = module.network.subnet_id
  availability_domain    = var.availability_domain
  instance_shape         = var.instance_shape
  instance_ocpus         = var.instance_ocpus
  instance_memory_gbs    = var.instance_memory_gbs
  boot_volume_size_gbs   = var.boot_volume_size_gbs
  ssh_public_key         = var.ssh_public_key
  user_data              = local.user_data
  hostname_label         = var.hostname_label
  image_id               = var.image_id
  image_operating_system = var.image_operating_system
  image_os_version       = var.image_operating_system_version
  freeform_tags          = local.tags
}
